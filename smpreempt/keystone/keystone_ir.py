"""Reproducible IR capture plan from an existing Keystone compilation database.

Never invent include paths/defines or substitute mock OpenSBI headers. The source
checkout stays untouched; compiler outputs go to the supplied output directory.
"""
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ir_arguments(arguments, source, output, clang, target=None):
    if not arguments:
        raise ValueError('empty compilation command')
    if any(a.startswith('@') for a in arguments[1:]):
        raise ValueError('response-file commands require explicit expansion before capture')
    if any(a in ('&&', '||', ';', '|', '>', '<') for a in arguments):
        raise ValueError('shell pipelines/redirections are not compilation arguments')
    original = arguments[0]
    if not any(name in Path(original).name for name in ('gcc', 'clang', 'cc')):
        raise ValueError('compiler wrappers must be expanded in compile_commands.json')
    preserved, removed = [], []
    skip = False
    separate = {'-o', '-MF', '-MT', '-MQ', '-MJ'}
    for arg in arguments[1:]:
        if skip:
            removed.append(arg)
            skip = False
            continue
        if arg in separate:
            removed.append(arg)
            skip = True
        elif arg in ('-c', '-S', '-emit-llvm', '-MD', '-MMD', '-MP', '-M', '-MM') or arg.startswith('-save-temps'):
            removed.append(arg)
        elif any(arg.startswith(prefix) and arg != prefix for prefix in ('-o', '-MF', '-MT', '-MQ', '-MJ')):
            removed.append(arg)
        else:
            preserved.append(arg)
    if skip:
        raise ValueError('compilation option lacks its argument')
    # Cross GCC's executable name carries the target; replacing it must not
    # silently compile the monitor as a host program.
    has_target = any(a == '-target' or a.startswith('--target=') for a in preserved)
    if not has_target and not target and 'clang' not in Path(original).name:
        raise ValueError('replacing GCC requires explicit --target to preserve the target architecture')
    command = [clang]
    if target:
        command.append('--target='+target)
    command += preserved + ['-S', '-emit-llvm', '-o', str(output)]
    return command, removed


def prepare_capture(repo, output_dir, *, source='sm/src/enclave.c', compilation_database=None,
                    clang=None, target=None):
    repo, output_dir = Path(repo).expanduser().resolve(), Path(output_dir).resolve()
    if not repo.is_dir():
        raise ValueError('Keystone repository does not exist: '+str(repo))
    source_path = (repo/source).resolve()
    if not source_path.is_file() or not source_path.is_relative_to(repo):
        raise ValueError('source must be an existing file within the repository')
    def git(*args):
        p = subprocess.run(['git', '-C', str(repo), *args], text=True, capture_output=True)
        return p.stdout.strip() if p.returncode == 0 else None
    compiler = clang or next((shutil.which(n) for n in ('clang-20', 'clang-18', 'clang') if shutil.which(n)), None)
    compiler = shutil.which(compiler) if compiler else None
    manifest = dict(schema='smpreempt.keystone-ir-capture.v1', repository=str(repo),
        commit=git('rev-parse', 'HEAD'), worktree_status=git('status', '--porcelain'),
        submodules=git('submodule', 'status'), source=str(source_path), source_sha256=digest(source_path),
        output=str(output_dir/'enclave.ll'), compiler=compiler, target_override=target,
        readiness='missing_dependencies', blockers=[], command=None,
        note='capture of a translation unit, not a full firmware build or proof')
    if compiler is None:
        manifest['blockers'].append('Clang executable is unavailable')
    db = Path(compilation_database).expanduser().resolve() if compilation_database else repo/'compile_commands.json'
    manifest['compilation_database'] = str(db)
    if not db.is_file():
        manifest['blockers'].append('compilation database is unavailable; original includes/defines/platform flags are required')
        return manifest
    records = json.loads(db.read_text())
    if not isinstance(records, list):
        raise ValueError('compilation database must contain a list')
    matches = []
    for record in records:
        directory = Path(record['directory'])
        if not directory.is_absolute():
            directory = (db.parent/directory).resolve()
        file = (directory/record['file']).resolve()
        if file == source_path:
            matches.append((record, directory))
    if len(matches) != 1:
        manifest['blockers'].append(f'expected one compile command for source; found {len(matches)}')
        return manifest
    record, directory = matches[0]
    args = record.get('arguments')
    if args is None:
        args = shlex.split(record['command'])
    if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
        raise ValueError('compilation arguments must be strings')
    manifest.update(directory=str(directory), original_arguments=args, compilation_database_sha256=digest(db))
    try:
        command, removed = ir_arguments(args, source_path, output_dir/'enclave.ll', compiler or 'clang', target)
        manifest.update(command=command, removed_output_options=removed)
    except ValueError as exc:
        manifest['blockers'].append(str(exc))
    if not directory.is_dir():
        manifest['blockers'].append('original compilation working directory is unavailable')
    manifest['readiness'] = 'ready' if not manifest['blockers'] else 'missing_dependencies'
    return manifest


def capture(manifest):
    if manifest['readiness'] != 'ready':
        return dict(manifest, status='not_run')
    out = Path(manifest['output'])
    out.parent.mkdir(parents=True, exist_ok=True)
    version = subprocess.run([manifest['compiler'], '--version'], text=True, capture_output=True)
    result = subprocess.run(manifest['command'], cwd=manifest['directory'], text=True, capture_output=True)
    report = dict(manifest, compiler_version=version.stdout.strip(), returncode=result.returncode,
                  stdout=result.stdout, stderr=result.stderr,
                  status='captured' if result.returncode == 0 and out.is_file() else 'compile_failed')
    if report['status'] == 'captured':
        report['ir_sha256'] = digest(out)
    return report


def generic_compile_database(repo, opensbi, clang, output_dir, *, full_build=False):
    """Recover the real C command from OpenSBI make for a standalone generic TU.

    This is an explicitly selected reference profile, not a reconstruction of
    an unknown board's deployed firmware. make may generate dependency files
    under O=output_dir; it does not compile/link the firmware.
    """
    repo, opensbi, output_dir = (Path(p).expanduser().resolve() for p in (repo, opensbi, output_dir))
    compiler = shutil.which(clang)
    if compiler is None or not (opensbi/'Makefile').is_file():
        raise ValueError('generic capture requires an existing Clang and OpenSBI checkout')
    if output_dir.is_relative_to(repo) or output_dir.is_relative_to(opensbi):
        raise ValueError('capture output must be outside both source checkouts')
    def command(*args):
        p = subprocess.run(args, text=True, capture_output=True)
        if p.returncode:
            raise ValueError(p.stderr.strip() or 'command failed')
        return p.stdout.strip()
    version = command('git', '-C', str(opensbi), 'describe', '--tags', '--exact-match')
    config = repo/'overlays/keystone/configs/riscv64_generic_defconfig'
    if not config.is_file() or 'BR2_TARGET_OPENSBI_CUSTOM_VERSION_VALUE="1.1"' not in config.read_text() or version != 'v1.1':
        raise ValueError('this reference profile requires the repository generic config and OpenSBI v1.1')
    output_dir.mkdir(parents=True, exist_ok=True)
    build = output_dir/'opensbi-build'
    targets = [build/'platform/generic/../../src/enclave.o', build/'lib/sbi/sbi_string.o']
    if full_build:
        targets = [build/'platform/generic/lib/libplatsbi.a']
    make = ['make', '-n', '-C', str(opensbi), 'O='+str(build),
            'PLATFORM_DIR='+str(repo/'sm/plat'), 'KEYSTONE_SM='+str(repo/'sm'),
            'KEYSTONE_PLATFORM=generic', 'KEYSTONE_SDK_DIR='+str(repo/'sdk'),
            'PLATFORM=generic', 'LLVM=1', 'CROSS_COMPILE=riscv64-unknown-elf-', 'CC='+compiler, *map(str, targets)]
    if full_build:
        make.insert(2, '-B')
    run = subprocess.run(make, text=True, capture_output=True)
    (output_dir/'make-command.json').write_text(json.dumps(make, indent=2)+'\n')
    (output_dir/'make-dry-run.log').write_text(run.stdout+run.stderr)
    if run.returncode:
        raise ValueError('OpenSBI make dry-run failed; see '+str(output_dir/'make-dry-run.log'))
    records = compilation_records(run.stdout, compiler, opensbi)
    if not full_build:
        records = [r for r in records if Path(r['file']).name in ('enclave.c', 'sbi_string.c')]
        if len(records) != 2:
            raise ValueError('expected enclave.c and sbi_string.c commands from the make rules')
    elif not records:
        raise ValueError('no compilation commands found in full platform make rules')
    db = output_dir/'compile_commands.json'
    db.write_text(json.dumps(records, indent=2)+'\n')
    dependencies = {}
    for root in (repo/'sm/src', repo/'sdk/include/shared', opensbi/'include'):
        for file in sorted(root.rglob('*.h')):
            dependencies[str(file)] = digest(file)
    profile = dict(profile='standalone generic RV64 translation unit; not deployed-board build equivalence',
                   opensbi_repository=str(opensbi), opensbi_version=version,
                   opensbi_commit=command('git', '-C', str(opensbi), 'rev-parse', 'HEAD'),
                   opensbi_status=command('git', '-C', str(opensbi), 'status', '--porcelain'),
                   config=str(config), config_sha256=digest(config), header_sha256=dependencies)
    profile['capture_scope'] = 'all platform archive compilation units' if full_build else 'enclave and string translation units'
    return db, profile


def capture_opensbi_string(manifest, profile):
    db = json.loads(Path(manifest['compilation_database']).read_text())
    source = Path(profile['opensbi_repository'])/'lib/sbi/sbi_string.c'
    records = [r for r in db if Path(r['file']).resolve() == source.resolve()]
    if len(records) != 1 or not manifest.get('compiler'):
        raise ValueError('cannot find the captured sbi_string.c command/compiler')
    output = Path(manifest['output']).parent/'sbi_string.ll'
    args, removed = ir_arguments(records[0]['arguments'], source, output, manifest['compiler'])
    dependency = dict(readiness='ready', source=str(source), source_sha256=digest(source),
                      output=str(output), compiler=manifest['compiler'], command=args,
                      directory=records[0]['directory'], removed_output_options=removed,
                      commit=profile['opensbi_commit'])
    return capture(dependency)


def compilation_records(log, compiler, directory):
    """Parse only compiler argv from known make rules; never execute log text."""
    records = []
    seen = set()
    for line in log.splitlines():
        marker = '; '+compiler+' '
        if marker not in line:
            continue
        args = [compiler]+shlex.split(line.split(marker, 1)[1])
        if '-c' not in args:
            continue
        source = Path(args[args.index('-c')+1])
        source = (Path(directory)/source).resolve()
        if source in seen:
            raise ValueError('multiple compile commands for '+str(source))
        seen.add(source)
        records.append(dict(directory=str(directory), file=str(source), arguments=args))
    return records


def capture_database(database, output_dir, clang, *, target=None):
    """Compile every C TU with its own build flags; inventory assembly separately.

    Failed/missing units prevent linking. Each unit has a collision-free output
    and retains original argv and content hashes. No flags are borrowed from a
    different translation unit.
    """
    database, output_dir = Path(database).resolve(), Path(output_dir).resolve()
    compiler = shutil.which(clang)
    if compiler is None:
        raise ValueError('Clang executable is unavailable')
    records = json.loads(database.read_text())
    if not isinstance(records, list):
        raise ValueError('compilation database must contain a list')
    reports, skipped = [], []
    seen = set()
    for record in records:
        directory = Path(record['directory'])
        if not directory.is_absolute():
            directory = database.parent/directory
        directory = directory.resolve()
        source = (directory/record['file']).resolve()
        if source in seen:
            raise ValueError('multiple compile commands for '+str(source))
        seen.add(source)
        if source.suffix != '.c':
            skipped.append(dict(source=str(source), reason='non-C translation unit; assembly semantics require separate extraction'))
            continue
        args = record.get('arguments')
        if args is None:
            args = shlex.split(record['command'])
        if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
            raise ValueError('compilation arguments must be strings')
        name = source.stem+'-'+hashlib.sha256(str(source).encode()).hexdigest()[:16]+'.ll'
        output = output_dir/'units'/name
        command, removed = ir_arguments(args, source, output, compiler, target)
        manifest = dict(readiness='ready' if source.is_file() else 'missing_dependencies',
            source=str(source), source_sha256=digest(source) if source.is_file() else None,
            output=str(output), directory=str(directory), compiler=compiler,
            original_arguments=args, command=command, removed_output_options=removed,
            blockers=[] if source.is_file() else ['source is missing; generated sources must be built first'])
        reports.append(capture(manifest))
    output_dir.mkdir(parents=True, exist_ok=True)
    result = dict(schema='smpreempt.ir-batch-capture.v1', compilation_database=str(database),
        compilation_database_sha256=digest(database), units=reports, skipped=skipped,
        status='captured' if reports and all(r['status']=='captured' for r in reports) else 'incomplete',
        scope='all C records; assembly units inventoried, not translated to LLVM')
    (output_dir/'batch-capture.json').write_text(json.dumps(result, indent=2)+'\n')
    return result
