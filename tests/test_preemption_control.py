import importlib.util
import unittest

from smpreempt.preemption import PreemptionControl
from smpreempt.riscv_model import Insn, Machine, PM
from smpreempt.scenarios import demo_machine

HAS_Z3 = importlib.util.find_spec("z3") is not None
if HAS_Z3:
    import z3
    from smpreempt.preemption import check_switch
    from smpreempt.symbolic_system import BoundedSystem, STEP, PREEMPT, RESUME, RUN, find_counterexample


def temporarily_exposed():
    state, template, snippet, _ = demo_machine()
    machine = Machine(state).instruction(Insn("LD", rd=7, rs1=10))
    machine = machine.instruction(snippet[0])
    return machine, template


class ConcreteControlTests(unittest.TestCase):
    def test_request_is_deferred_then_serviced_after_restore(self):
        machine, _ = temporarily_exposed()
        controller, pm = PreemptionControl(), PM(None)
        deferred = controller.request(machine, pm)
        self.assertTrue(deferred.pending)
        self.assertEqual(deferred.c, "SM")
        self.assertEqual(deferred.S, machine.S)
        restored = deferred.instruction(Insn("CSRW", rs1=6, csr="pmpcfg0"))
        self.assertTrue(restored.pending)
        host = controller.request(restored, pm)
        self.assertEqual(host.c, "H")
        self.assertFalse(host.pending)
        resumed = host.resume(pm)
        self.assertEqual(resumed.S, restored.S)
        self.assertEqual(resumed.accessed, restored.accessed)

    def test_mechanism_and_admission_are_independent(self):
        machine, template = temporarily_exposed()
        self.assertTrue(PreemptionControl("always").allows(machine, PM(None)))
        self.assertEqual(PreemptionControl("always").request(machine, PM(None)).c, "H")
        self.assertFalse(PreemptionControl().allows(machine, PM(None)))
        self.assertTrue(PreemptionControl().allows(machine, PM(template)))

    def test_physical_lock_failure_defers_even_without_safety_guard(self):
        machine, template = temporarily_exposed()
        machine.S.P.cfg[0] |= 0x80
        deferred = PreemptionControl("always").request(machine, PM(template))
        self.assertTrue(deferred.pending)
        self.assertEqual(deferred.c, "SM")


@unittest.skipUnless(HAS_Z3, "install requirements-smt.txt to run symbolic tests")
class SymbolicControlTests(unittest.TestCase):
    def test_arbitrary_states_distinguish_mechanism_only_from_guarded(self):
        _, template, _, _ = demo_machine()
        always = check_switch(PM(template), PreemptionControl("always"))
        guarded = check_switch(PM(template), PreemptionControl())
        self.assertEqual(always["status"], "counterexample")
        self.assertEqual(always["checks"]["install_and_restore"]["status"], "sat")
        self.assertEqual(always["checks"]["direct_isolation"]["status"], "sat")
        self.assertEqual(guarded["status"], "valid_for_K0_obligations")
        self.assertEqual(guarded["admission"]["status"], "sat")
        self.assertEqual(guarded["denial"]["status"], "sat")
        self.assertTrue(all(c["status"] == "unsat" for c in guarded["checks"].values()))

    def test_empty_domain_and_total_denial_are_not_success(self):
        state, template, _, _ = demo_machine()
        empty = check_switch(PM(template), constrain=lambda before: z3.BoolVal(False))
        self.assertEqual(empty["status"], "empty_domain")
        state.P.cfg = [0] * 8  # No executable Host entry, so G rejects all states.
        denied = check_switch(PM(state.P))
        self.assertEqual(denied["status"], "no_admitted_state")
        state.P.cfg[0] = 2
        with self.assertRaises(ValueError):
            check_switch(PM(state.P))

    def test_pending_request_survives_step_and_forces_service(self):
        machine, _ = temporarily_exposed()
        pc = machine.S.E.pc
        program = {pc: Insn("CSRW", rs1=6, csr="pmpcfg0"), pc + 4: Insn("JAL", imm=0)}
        system = BoundedSystem(machine, program, PM(None), control=PreemptionControl())
        for action in (PREEMPT, STEP, PREEMPT, RESUME):
            system.extend()
            system.solver.add(system.choices[-1].action == action)
        system.solver.add(system.states[-1].status == RUN)
        self.assertEqual(system.solver.check(), z3.sat)
        concrete, trace = system.replay(system.solver.model(), 4)
        self.assertEqual(trace[0]["outcome"], "deferred")
        self.assertEqual(concrete.S.E.pc, pc + 4)
        self.assertFalse(concrete.pending)
        self.assertEqual(concrete.c, "SM")
        # Once the pending request is safe to service, STEP cannot skip it.
        system = BoundedSystem(machine, program, PM(None), control=PreemptionControl())
        for action in (PREEMPT, STEP, STEP):
            system.extend()
            system.solver.add(system.choices[-1].action == action)
        self.assertEqual(system.solver.check(), z3.unsat)

    def test_concrete_and_symbolic_control_agree(self):
        machine, template = temporarily_exposed()
        from smpreempt.symbolic_system import SystemState
        from smpreempt.preemption import switchout_state
        for mode in ("always", "isolation"):
            for pm in (PM(None), PM(template)):
                controller = PreemptionControl(mode)
                before = SystemState.initial(machine)
                expression = controller.symbolic_allowed(before, switchout_state(before, pm), pm)
                expected = controller.allows(machine, pm)
                solver = z3.Solver()
                solver.add(expression != expected)
                self.assertEqual(solver.check(), z3.unsat)

    def test_deferral_reachable_does_not_mean_host_was_run(self):
        machine, _ = temporarily_exposed()
        pc = machine.S.E.pc
        result = find_counterexample(machine, {pc: Insn("JAL", imm=0)}, PM(None),
                                     bound=1, control=PreemptionControl())
        self.assertEqual(result["status"], "bounded_unsat")
        self.assertTrue(result["deferral_reachable"])


if __name__ == "__main__":
    unittest.main()
