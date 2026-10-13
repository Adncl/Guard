"""Build linked LLVM bitcode and Clang control-flow metadata from compile_commands.json."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess


def compile_project(database, output, plugin, target='sol', ast_only=False):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    records = json.loads(Path(database).read_text())
    objects = []
    commands = []
    for i, record in enumerate(records):
        args = record.get('arguments') or shlex.split(record['command'])
        # CMake's compile database also contains test targets; link one target.
        object_name = args[args.index('-o') + 1] if '-o' in args else ''
        if target and f'{target}.dir/' not in object_name:
            continue
        cleaned = []
        skip = False
        for arg in args[1:]:
            if skip:
                skip = False
                continue
            if arg in ('-o', '-MF', '-MT', '-MQ'):
                skip = True
            elif arg not in ('-c', '-MD', '-MMD', '-MP', '-Werror') and not arg.startswith('-O'):
                cleaned.append(arg)
        command = None
        if not ast_only:
            bc = output / f'{i:04}_{Path(record["file"]).stem}.bc'
            command = ['clang-14', *cleaned, '-g', '-O0', '-Xclang', '-disable-O0-optnone',
                       '-fno-discard-value-names', '-emit-llvm', '-c', '-o', str(bc)]
            subprocess.run(command, cwd=record['directory'], check=True, capture_output=True)
            objects.append(str(bc))
        ast_cmd = ['clang-14', *cleaned, '-Xclang', '-load', '-Xclang', str(Path(plugin).resolve()),
                   '-Xclang', '-plugin', '-Xclang', 'cf-analyzer', '-fsyntax-only']
        subprocess.run(ast_cmd, cwd=record['directory'], check=True, capture_output=True)
        if command:
            commands.append({'cwd': record['directory'], 'command': command})
        commands.append({'cwd': record['directory'], 'command': ast_cmd})
    if not objects:
        if not ast_only:
            raise ValueError(f'No compile commands for target {target!r}')
    (output / 'commands.json').write_text(json.dumps(commands, indent=2))
    if ast_only:
        print(f'Generated AST metadata from {len(commands)} commands')
        return
    subprocess.run(['llvm-link-14', *objects, '-o', str(output / (target + '.bc'))], check=True)
    subprocess.run(['opt-14', '-passes=mem2reg', str(output / (target + '.bc')), '-o', str(output / (target + '_ssa.bc'))], check=True)
    subprocess.run(['llvm-dis-14', str(output / (target + '.bc')), '-o', str(output / (target + '.ll'))], check=True)
    print(f'Built whole-program IR from {len(objects)} translation units')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('database')
    p.add_argument('output')
    p.add_argument('--plugin', required=True)
    p.add_argument('--target', default='sol')
    p.add_argument('--ast-only', action='store_true',
                   help='Generate Clang control-flow metadata without linking temporary bitcode')
    a = p.parse_args()
    compile_project(a.database, a.output, a.plugin, a.target, a.ast_only)
