import importlib.util
import random
import unittest

HAS_Z3 = importlib.util.find_spec("z3") is not None
if HAS_Z3:
    import z3
    from smpreempt.model.symbolic_instructions import InstructionState, instruction_transition, load64, store64
    from smpreempt.model.riscv_model import Insn, Machine, Unsupported, MSTATUS_MPRV
    from smpreempt.scenarios import demo_machine


@unittest.skipUnless(HAS_Z3, "install requirements-smt.txt to run SMT tests")
class InstructionTransitionTests(unittest.TestCase):
    def test_store_load_aliasing_and_little_endian(self):
        memory = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
        address, value = z3.BitVecs("memory_address memory_value", 64)
        stored = store64(memory, address, value)
        self.assert_unsat(load64(stored, address) != value)
        self.assert_unsat(z3.Select(stored, address) != z3.Extract(7, 0, value))

    def assert_unsat(self, *constraints):
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(*constraints)
        self.assertEqual(solver.check(), z3.unsat)

    def test_concrete_differential_all_instructions(self):
        rng = random.Random(42)
        instructions = [Insn(op, rd=3, rs1=1, rs2=2, imm=-8)
                        for op in ("ADD", "ADDI", "XOR", "AND", "BEQ", "JAL", "JALR", "LD", "SD")]
        instructions += [Insn("LD", rd=1, rs1=1), Insn("LD", rd=0, rs1=1),
                         Insn("JALR", rd=1, rs1=1), Insn("ADDI", rd=0, rs1=1, imm=1)]
        for context, priv in (("SM", "M"), ("C", "U"), ("H", "S")):
            for instruction in instructions:
                with self.subTest(context=context, instruction=instruction):
                    s, _, _, _ = demo_machine()
                    s.E.priv = priv
                    s.E.pc = (1 << 64) - 4
                    s.E.put(1, 0x2008)
                    s.E.put(2, rng.getrandbits(64))
                    s.M.store(0x2000, 8, rng.getrandbits(64))
                    m = Machine(s, context, accessed=frozenset({0x3000}))
                    t = instruction_transition(InstructionState.from_machine(m), instruction, m)
                    expected = InstructionState.from_machine(m.instruction(instruction))
                    self.assert_unsat(z3.Not(t.success))
                    self.assert_unsat(t.success, z3.Not(t.next_state.same_as(expected)))

    def test_arbitrary_symbolic_arithmetic_and_branch(self):
        s, _, _, _ = demo_machine()
        env = Machine(s)
        before = InstructionState.fresh("arbitrary")
        add = instruction_transition(before, Insn("ADD", rd=1, rs1=1, rs2=2), env)
        self.assert_unsat(add.next_state.registers[1] != before.registers[1] + before.registers[2])
        branch = instruction_transition(before, Insn("BEQ", rs1=1, rs2=2, imm=-8), env)
        self.assert_unsat(before.registers[1] == before.registers[2],
                          branch.next_state.pc != before.pc - 8)
        self.assert_unsat(before.registers[1] != before.registers[2],
                          branch.next_state.pc != before.pc + 4)

    def test_history_monotonicity_memory_frame_and_relation(self):
        s, _, _, _ = demo_machine()
        before = InstructionState.fresh("store")
        after = InstructionState.fresh("after")
        t = instruction_transition(before, Insn("SD", rs1=1, rs2=2), Machine(s))
        witness = z3.BitVec("byte_witness", 64)
        self.assert_unsat(t.relation(after), z3.Select(before.history, witness),
                          z3.Not(z3.Select(after.history, witness)))
        outside = z3.And(*[witness != before.registers[1] + i for i in range(8)])
        self.assert_unsat(t.relation(after), outside,
                          z3.Select(before.memory, witness) != z3.Select(after.memory, witness))
        self.assert_unsat(t.relation(after),
                          z3.Not(z3.Select(after.history, before.registers[1] + 7)))

    def test_fault_alignment_and_mprv(self):
        s, _, _, _ = demo_machine()
        s.E.priv = "S"
        s.E.put(1, 0x8000)
        env = Machine(s, "C")
        before = InstructionState.from_machine(env)
        t = instruction_transition(before, Insn("LD", rs1=1), env)
        self.assert_unsat(t.success)
        self.assert_unsat(z3.Not(t.access_fault))
        s.E.priv = "M"
        s.E.csr["mstatus"] = MSTATUS_MPRV | (1 << 11)
        self.assert_unsat(instruction_transition(before, Insn("LD", rs1=1), Machine(s)).success)
        s.E.put(1, 0x8001)
        env = Machine(s)
        t = instruction_transition(InstructionState.from_machine(env), Insn("LD", rs1=1), env)
        self.assert_unsat(z3.Not(t.misaligned))
        self.assert_unsat(t.access_fault)

    def test_host_does_not_grow_history_and_unsupported_is_explicit(self):
        s, _, _, _ = demo_machine()
        s.E.priv = "S"
        env = Machine(s, "H")
        before = InstructionState.fresh("host")
        t = instruction_transition(before, Insn("LD", rd=0, rs1=1), env)
        self.assert_unsat(t.next_state.history != before.history)
        for insn in (Insn("ECALL"), Insn("CSRW", csr="satp")):
            with self.assertRaises(Unsupported):
                instruction_transition(before, insn, env)
        s.V.satp = 8 << 60
        with self.assertRaises(Unsupported):
            instruction_transition(before, Insn("LD", rs1=1), env)


if __name__ == "__main__":
    unittest.main()
