#!/usr/bin/env python3
"""Compare fixed Go test binaries in sequential, alternating A/B pairs."""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    parser.add_argument('--bench', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--count', type=int, default=10)
    parser.add_argument('--cpu', type=int, default=1)
    parser.add_argument('--time', default='750ms')
    args = parser.parse_args()
    if args.count < 1 or args.cpu < 1:
        parser.error('--count and --cpu must be positive')
    states = [('before', args.before.resolve()), ('after', args.after.resolve())]
    for _, binary in states:
        if not binary.is_file():
            parser.error(f'missing test binary: {binary}')
    args.out.mkdir(parents=True, exist_ok=True)
    for label, _ in states:
        (args.out / f'{label}.txt').write_text('')
    env = os.environ.copy()
    # External backend overrides would invalidate comparison of the defaults.
    for name in ('GOHASH160MB_FORCE', 'GOSHA256MB_FORCE',
                 'GORIPEMD160MB_FORCE', 'GOSECP256K1FIELD_FORCE'):
        env.pop(name, None)
    env['GOMAXPROCS'] = str(args.cpu)
    expected_names = None
    for sample in range(args.count):
        order = states if sample % 2 == 0 else list(reversed(states))
        for label, binary in order:
            result = subprocess.run(
                [str(binary), '-test.run=^$', f'-test.bench={args.bench}',
                 '-test.benchmem', f'-test.benchtime={args.time}',
                 '-test.count=1', f'-test.cpu={args.cpu}'],
                env=env, text=True, capture_output=True,
            )
            with (args.out / f'{label}.txt').open('a') as output:
                output.write(result.stdout)
            if result.returncode:
                print(result.stderr, file=sys.stderr)
                raise SystemExit(f'{label} benchmark failed: {result.returncode}')
            names = {line.split()[0] for line in result.stdout.splitlines()
                     if line.startswith('Benchmark')}
            if not names:
                raise SystemExit(f'{label}: no benchmark rows matched {args.bench!r}')
            if expected_names is None:
                expected_names = names
            elif names != expected_names:
                raise SystemExit(f'{label}: benchmark names differ: '
                                 f'{sorted(names)} vs {sorted(expected_names)}')
        print(f'{args.out.name}: pair {sample + 1}/{args.count}', flush=True)
    print(f'benchstat {args.out}/before.txt {args.out}/after.txt', flush=True)


if __name__ == '__main__':
    main()
