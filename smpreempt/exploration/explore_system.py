"""Check arbitrary interruption states, or explore a bounded SM program."""
import argparse
import json

from smpreempt.model.riscv_model import Insn, Machine, PM
from smpreempt.scenarios import demo_machine
from smpreempt.analysis.symbolic_system import find_counterexample
from smpreempt.analysis.preemption import PreemptionControl, check_switch
from smpreempt.analysis.host_attacks import analyze_host_attacks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bound", type=int, default=None, help="program analysis only (default: 5)")
    parser.add_argument("--timeout-ms", type=int, default=10000)
    parser.add_argument("--analysis", choices=("attacks", "pmp-sync", "states", "program"), default="attacks",
                        help="attacks: Host-only data; pmp-sync: fencing; states: W/G; program: instructions")
    args = parser.parse_args()
    if args.analysis != "program" and args.bound is not None:
        parser.error("--bound applies only to --analysis program")
    state, template, snippet, _ = demo_machine()
    if args.analysis == "pmp-sync":
        import z3
        from smpreempt.model.symbolic_pmp import SymbolicPMP
        state.P.cfg[0] = 0  # previously public S-mode mapping with legal R/W
        prior = state.P
        history = z3.Store(z3.K(z3.BitVecSort(64), z3.BoolVal(False)),
                           z3.BitVecVal(0x8000, 64), z3.BoolVal(True))
        def safe_snapshot(snapshot):
            return z3.And(snapshot.pmp.same_as(SymbolicPMP.concrete(template)),
                          snapshot.q.history == history,
                          z3.Select(snapshot.q.memory, snapshot.cache.va) == 0xA5)
        reports = {label: analyze_host_attacks(PM(template, sync_pmp=sync),
                    constrain=safe_snapshot, cache_origin_pmp=prior, stale_only=True,
                    timeout_ms=args.timeout_ms)
                   for label, sync in (("without_sfence", False), ("with_sfence", True))}
        print(json.dumps(reports, indent=2))
        return
    if args.analysis == "attacks":
        reports = {"passthrough": analyze_host_attacks(PM(None), timeout_ms=args.timeout_ms),
                   "fixed_template": analyze_host_attacks(PM(template), timeout_ms=args.timeout_ms)}
        print(json.dumps(reports, indent=2))
        return
    if args.analysis == "states":
        reports = {mode: check_switch(PM(template), PreemptionControl(mode), timeout_ms=args.timeout_ms)
                   for mode in ("always", "isolation")}
        print(json.dumps(reports, indent=2))
        return
    # Establish history first, then execute the PMP update/scrub sequence.
    instructions = [Insn("LD", rd=7, rs1=10)] + snippet
    program = {state.E.pc + 4 * i: insn for i, insn in enumerate(instructions)}
    exits = frozenset({state.E.pc + 4 * len(instructions)})
    reports = {}
    for label, pm, control in (("passthrough", PM(None), PreemptionControl("always")),
                      ("trusted_template", PM(template), PreemptionControl("isolation"))):
        reports[label] = find_counterexample(Machine(state), program, pm,
            bound=5 if args.bound is None else args.bound, exits=exits,
            timeout_ms=args.timeout_ms, control=control)
    print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()
