import importlib.util
import unittest

from smpreempt.model.riscv_model import AccessFault, CachedAccess, Insn, Machine, PM, Unsupported, step
from smpreempt.scenarios import demo_machine

HAS_Z3 = importlib.util.find_spec("z3") is not None
if HAS_Z3:
    import z3
    from smpreempt.analysis.host_attacks import analyze_host_attacks
    from smpreempt.model.symbolic_cache import SymbolicCachedAccess
    from smpreempt.model.symbolic_pmp import SymbolicPMP
    from smpreempt.analysis.symbolic_system import BoundedSystem, STEP, PREEMPT, HOST_LD, RUN, find_counterexample


def cached_snapshot(privilege="S"):
    state, safe, _, _ = demo_machine()
    state.P.cfg[0] = 0
    state.V.cache_pmp_permissions = True
    state.E.priv = privilege
    state.E.put(10, 0x8000)
    state.M.store(0x8000, 8, 0)
    state = step(state, Insn("LD", rd=12, rs1=10))
    state.E.priv = "M"
    state.E.pc = 0x4000
    state.E.put(11, 0xA5)
    state = step(state, Insn("SD", rs1=10, rs2=11), fill_cache=False)
    state.E.put(5, sum(c << (8 * i) for i, c in enumerate(safe.cfg)))
    state = step(state, Insn("CSRW", rs1=5, csr="pmpcfg0"))
    return state, safe


class ConcreteSyncTests(unittest.TestCase):
    def test_current_pmp_denies_but_cached_result_can_allow(self):
        state, _ = cached_snapshot()
        state.E.priv = "S"
        with self.assertRaises(AccessFault):
            step(state, Insn("LD", rd=12, rs1=10))
        loaded = step(state, Insn("LD", rd=12, rs1=10), use_cached=True)
        self.assertEqual(loaded.E.get(12), 0xA5)
        stored = step(state, Insn("SD", rs1=10, rs2=0), use_cached=True)
        self.assertEqual(stored.M.load(0x8000, 8), 0)

    def test_fence_invalidates_but_satp_write_does_not(self):
        state, _ = cached_snapshot()
        original = state.V.cached
        state.E.put(6, 8 << 60)
        state = step(state, Insn("CSRW", rs1=6, csr="satp"))
        self.assertEqual(state.V.cached, original)
        state = step(state, Insn("CSRW", rs1=0, csr="satp"))
        self.assertEqual(state.V.cached, original)
        state = step(state, Insn("SFENCE.VMA"))
        self.assertIsNone(state.V.cached)
        state.E.priv = "S"
        with self.assertRaises(AccessFault):
            step(state, Insn("LD", rs1=10), use_cached=True)
        with self.assertRaises(Unsupported):
            step(state, Insn("SFENCE.VMA", rs1=10))

    def test_m_mode_permissions_cannot_be_reused_as_s_mode(self):
        state, _ = cached_snapshot("M")
        state.E.priv = "S"
        with self.assertRaises(AccessFault):
            step(state, Insn("LD", rs1=10), use_cached=True)

    def test_cache_cannot_be_created_from_a_denied_prior_access(self):
        state, safe, _, _ = demo_machine()
        with self.assertRaises(ValueError):
            CachedAccess(0x8000, 0x8000, 8, "S", safe, "R")
        state.P.cfg[0] = 0
        entry = CachedAccess(0x8000, 0x8000, 8, "S", state.P, "R")
        state.P.cfg[0] = safe.cfg[0]
        self.assertTrue(entry.allows("R"))  # provenance is a snapshot, not an alias

    def test_pm_flush_is_explicit_and_resume_does_not_restore_cache(self):
        state, safe = cached_snapshot()
        unsafe, _ = PM(safe).switchout(state)
        self.assertIsNotNone(unsafe.V.cached)
        unsafe.E.put(10, 0x8000)
        self.assertEqual(step(unsafe, Insn("LD", rd=12, rs1=10), use_cached=True).E.get(12), 0xA5)
        pm = PM(safe, sync_pmp=True)
        host, slot = pm.switchout(state)
        self.assertIsNone(host.V.cached)
        self.assertIsNone(slot.V.cached)
        host.E.put(10, 0x2000)
        host = step(host, Insn("LD", rs1=10))
        self.assertIsNotNone(host.V.cached)
        resumed = pm.switchin(host, slot)
        self.assertIsNone(resumed.V.cached)
        self.assertEqual(resumed.E, state.E)


@unittest.skipUnless(HAS_Z3, "install requirements-smt.txt to run symbolic tests")
class SymbolicSyncTests(unittest.TestCase):
    def test_admission_considers_effective_cached_permissions(self):
        from smpreempt.analysis.preemption import PreemptionControl, switchout_state
        from smpreempt.analysis.symbolic_system import SystemState
        state, safe = cached_snapshot()
        machine = Machine(state, accessed=frozenset(range(0x8000, 0x8008)))
        control = PreemptionControl()
        for sync in (False, True):
            pm = PM(safe, sync_pmp=sync)
            self.assertEqual(control.allows(machine, pm), sync)
            initial = SystemState.initial(machine)
            solver = z3.Solver()
            solver.add(control.symbolic_allowed(initial, switchout_state(initial, pm), pm) != sync)
            self.assertEqual(solver.check(), z3.unsat)

    def test_no_fence_attack_and_fence_prevention_have_legal_provenance(self):
        prior_state, safe, _, _ = demo_machine()
        prior_state.P.cfg[0] = 0
        history = z3.Store(z3.K(z3.BitVecSort(64), z3.BoolVal(False)),
                           z3.BitVecVal(0x8000, 64), z3.BoolVal(True))
        def snapshot(s):
            return z3.And(s.pmp.same_as(SymbolicPMP.concrete(safe)), s.q.history == history,
                          z3.Select(s.q.memory, s.cache.va) == 0xA5)
        for sync in (False, True):
            result = analyze_host_attacks(PM(safe, sync_pmp=sync), constrain=snapshot,
                                         cache_origin_pmp=prior_state.P, stale_only=True)
            if sync:
                self.assertEqual(result["status"], "no_direct_data_attack_in_model")
                self.assertEqual(result["startup"]["host_start"]["status"], "sat")
                self.assertTrue(all(a["status"] == "unsat" for a in result["attacks"].values()))
            else:
                self.assertEqual(result["status"], "attack_found")
                for attack in result["attacks"].values():
                    witness = attack["witness"]
                    self.assertTrue(witness["cache_provenance_replayed"])
                    self.assertEqual(witness["host_trace"][0]["permission_source"], "cached")
                    self.assertEqual(witness["prior_trace"][0]["observed"], 0)
                self.assertEqual(result["attacks"]["protected_read"]["witness"]["host_trace"][0]["observed"], 0xA5)

    def test_bmc_models_fence_cache_selection_and_replay(self):
        state, safe = cached_snapshot()
        machine = Machine(state, accessed=frozenset(range(0x8000, 0x8008)))
        pc = state.E.pc
        for fenced in (False, True):
            program = {pc: Insn("SFENCE.VMA") if fenced else Insn("ADDI"),
                       pc + 4: Insn("JAL", imm=0)}
            system = BoundedSystem(machine, program, PM(safe))
            for action in (STEP, PREEMPT, HOST_LD):
                system.extend()
                choice = system.choices[-1]
                system.solver.add(choice.action == action)
                if action == HOST_LD:
                    system.solver.add(choice.address == 0x8000, choice.use_cached,
                                      choice.fill_cache == False)
            system.solver.add(system.states[-1].status == RUN)
            result = system.solver.check()
            self.assertEqual(result, z3.unsat if fenced else z3.sat)
            if not fenced:
                replayed, _ = system.replay(system.solver.model(), 3)
                self.assertEqual(replayed.S.E.get(12), 0xA5)

    def test_satp_transition_preserves_cache_and_nonbare_access_is_unsupported(self):
        state, safe = cached_snapshot()
        state.E.put(6, 8 << 60)
        pc = state.E.pc
        program = {pc: Insn("CSRW", rs1=6, csr="satp"),
                   pc + 4: Insn("CSRW", rs1=0, csr="satp"), pc + 8: Insn("SFENCE.VMA")}
        system = BoundedSystem(Machine(state), program, PM(safe))
        for _ in range(3):
            system.extend()
            system.solver.add(system.choices[-1].action == STEP)
        self.assertEqual(system.solver.check(), z3.sat)
        model = system.solver.model()
        self.assertTrue(z3.is_true(model.eval(system.states[1].cache.valid)))
        self.assertTrue(z3.is_true(model.eval(system.states[2].cache.valid)))
        self.assertTrue(z3.is_false(model.eval(system.states[3].cache.valid)))
        system.replay(model, 3)
        state.E.priv = "S"
        program = {pc: Insn("CSRW", rs1=6, csr="satp"), pc + 4: Insn("LD", rs1=10)}
        result = find_counterexample(Machine(state), program, PM(safe, sync_pmp=True), bound=2)
        self.assertEqual(result["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
