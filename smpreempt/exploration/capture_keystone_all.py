"""Capture all C units of a Keystone/OpenSBI generic platform archive."""
import argparse
import json
from pathlib import Path
import subprocess

from smpreempt.keystone.keystone_ir import generic_compile_database, capture_database, digest
from smpreempt.extraction.llvm_link import link_ir
from smpreempt.frontend.llvm import extract_llvm
from smpreempt.frontend.llvm_c import LLVMUnavailable


def run(repository, opensbi, clang, output_dir, *, library=None):
    out = Path(output_dir).resolve()
    db, profile = generic_compile_database(repository, opensbi, clang, out, full_build=True)
    records = json.loads(db.read_text())
    # Ask the actual build rules to produce generated C files for this configuration.
    # Do not evaluate shell fragments copied from the dry-run log.
    generated = sorted({r['file'] for r in records if r['file'].endswith('.c')
        and Path(r['file']).is_relative_to(out/'opensbi-build')})
    generation = None
    if generated:
        make = json.loads((out/'make-command.json').read_text())
        make = [a for a in make[:-1] if a not in ('-n', '-B')]+generated
        p = subprocess.run(make, capture_output=True, text=True)
        generation = dict(command=make, returncode=p.returncode, stdout=p.stdout, stderr=p.stderr)
        (out/'generation.json').write_text(json.dumps(generation, indent=2)+'\n')
        if p.returncode:
            raise ValueError('generated source build failed; see '+str(out/'generation.json'))
    batch = capture_database(db, out, clang)
    batch.update(reference_profile=profile, repository=str(Path(repository).expanduser().resolve()))
    p = subprocess.run(['git', '-C', batch['repository'], 'rev-parse', 'HEAD'], capture_output=True, text=True)
    batch['commit'] = p.stdout.strip() if not p.returncode else None
    if batch['status'] == 'captured':
        linked = out/'linked.ll'
        batch['link'] = link_ir([u['output'] for u in batch['units']], linked, library)
        report = extract_llvm(linked, library=library)
        definitions = {f['name'] for f in report['functions'] if not f['declaration']}
        calls = []
        indirect = []
        for f in report['functions']:
            for edge in f['transitions']:
                effect = edge['effect']
                if effect.get('callee_kind') == 'direct':
                    name = effect['callee']['name']
                    if name not in definitions:
                        calls.append(dict(function=f['name'], node=edge['source'], callee=name,
                                          intrinsic=name.startswith('llvm.')))
                elif effect.get('callee_kind') == 'indirect':
                    indirect.append(dict(function=f['name'], node=edge['source']))
        coverage = dict(input=report['input'], defined_functions=sorted(definitions),
                        unresolved_direct_calls=calls, indirect_calls=indirect,
                        note='Definition availability only; indirect callbacks, assembly, traps and hart execution are not resolved.')
        (out/'coverage.json').write_text(json.dumps(coverage, indent=2)+'\n')
        batch['coverage'] = dict(defined_functions=len(definitions),
            unresolved_direct_calls=len(calls), indirect_calls=len(indirect),
            linked_sha256=digest(linked))
    (out/'batch-capture.json').write_text(json.dumps(batch, indent=2)+'\n')
    return batch


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('repository')
    p.add_argument('--opensbi', required=True)
    p.add_argument('--clang', required=True)
    p.add_argument('--output-dir', default='results/keystone-complete-ir')
    p.add_argument('--llvm-library')
    args = p.parse_args()
    try:
        result = run(args.repository, args.opensbi, args.clang, args.output_dir, library=args.llvm_library)
    except (OSError, ValueError, LLVMUnavailable) as exc:
        p.error(str(exc))
    print(json.dumps(dict(status=result['status'], units=len(result['units']),
        captured=sum(u['status']=='captured' for u in result['units']),
        assembly_units=len(result['skipped']), coverage=result.get('coverage'),
        manifest=str(Path(args.output_dir)/'batch-capture.json')), indent=2))
    if result['status'] != 'captured':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
