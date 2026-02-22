#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for benchmark budget validation" >&2
  exit 7
fi

bench_output="$(mktemp)"
trap 'rm -f "$bench_output"' EXIT

go test -run '^$' -bench 'Benchmark(ScoreComputeDeterministic|RiskScoreDeterministic)$' -benchmem -count=5 ./core/score ./core/risk | tee "$bench_output"

python3 - "$bench_output" <<'PY'
import json
import math
import pathlib
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

output_path = pathlib.Path(sys.argv[1])
root = pathlib.Path('.')
bench_contract = json.loads((root / 'perf' / 'bench_baseline.json').read_text(encoding='utf-8'))
runtime_contract = json.loads((root / 'perf' / 'runtime_slo_budgets.json').read_text(encoding='utf-8'))
bench_entries = {item['name']: item for item in bench_contract['benchmarks']}

pattern = re.compile(r'^(Benchmark\S+)\s+\d+\s+([0-9]+(?:\.[0-9]+)?)\s+ns/op')
observed = {}
for line in output_path.read_text(encoding='utf-8').splitlines():
    match = pattern.match(line.strip())
    if not match:
        continue
    name = re.sub(r'-\d+$', '', match.group(1))
    value = float(match.group(2))
    observed.setdefault(name, []).append(value)

errors = []
for name, contract in bench_entries.items():
    values = observed.get(name, [])
    if not values:
        errors.append(f'missing benchmark output: {name}')
        continue
    median = statistics.median(values)
    limit = float(contract['median']) * float(contract['max_regression_factor'])
    if median > limit:
        errors.append(f'{name} median {median:.2f}ns/op exceeds limit {limit:.2f}ns/op')

wrkr_bin = root / '.tmp' / 'wrkr'
wrkr_bin.parent.mkdir(parents=True, exist_ok=True)
if not wrkr_bin.exists():
    subprocess.run(['go', 'build', '-o', str(wrkr_bin), './cmd/wrkr'], cwd=root, check=True)


def timed_run(cmd):
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    duration = time.perf_counter() - start
    return proc.returncode, duration, proc.stderr.strip()


def p95_ms(values):
    ordered = sorted(values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0] * 1000.0
    rank = 0.95 * (len(ordered) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return ordered[lower] * 1000.0
    fraction = rank - lower
    return (ordered[lower] + (ordered[upper] - ordered[lower]) * fraction) * 1000.0


def sample_command_runs(name, cmd, runs=5):
    durations = []
    for _ in range(runs):
        rc, duration, stderr = timed_run(cmd)
        if rc != 0:
            return [], f'{name} command failed with exit {rc}: {stderr}'
        durations.append(duration)
    return durations, ''


def enforce_command_budget(name, cmd, limit_ms, windows=2, runs_per_window=5):
    # Measure in independent windows so a single noisy burst on shared CI runners
    # does not create a false positive while sustained regressions still fail.
    observed = []
    for _ in range(windows):
        runs, sample_err = sample_command_runs(name, cmd, runs=runs_per_window)
        if sample_err:
            errors.append(sample_err)
            return
        measured = p95_ms(runs)
        observed.append(measured)
        if measured <= limit_ms:
            return
    errors.append(f'{name} p95 {min(observed):.2f}ms exceeds budget {limit_ms:.2f}ms after {windows} windows')


tmpdir = pathlib.Path(tempfile.mkdtemp(prefix='wrkr-perf-'))
try:
    repos100 = tmpdir / 'repos-100'
    repos500 = tmpdir / 'repos-500'
    for i in range(100):
        (repos100 / f'repo-{i:03d}').mkdir(parents=True, exist_ok=True)
    for i in range(500):
        (repos500 / f'repo-{i:03d}').mkdir(parents=True, exist_ok=True)

    state100 = tmpdir / 'state-100.json'
    state500 = tmpdir / 'state-500.json'

    rc, duration100, stderr100 = timed_run([str(wrkr_bin), 'scan', '--path', str(repos100), '--state', str(state100), '--json'])
    if rc != 0:
        errors.append(f'scan 100 repos failed with exit {rc}: {stderr100}')
    else:
        budget100 = float(runtime_contract['scan']['repos_100']['max_seconds'])
        if duration100 > budget100:
            errors.append(f'scan 100 repos took {duration100:.2f}s (budget {budget100:.2f}s)')

    rc, duration500, stderr500 = timed_run([str(wrkr_bin), 'scan', '--path', str(repos500), '--state', str(state500), '--json'])
    if rc != 0:
        errors.append(f'scan 500 repos failed with exit {rc}: {stderr500}')
    else:
        budget500 = float(runtime_contract['scan']['repos_500']['max_seconds'])
        if duration500 > budget500:
            errors.append(f'scan 500 repos took {duration500:.2f}s (budget {budget500:.2f}s)')

    baseline = tmpdir / 'baseline-100.json'
    rc, _, stderr = timed_run([str(wrkr_bin), 'regress', 'init', '--baseline', str(state100), '--output', str(baseline), '--json'])
    if rc != 0:
        errors.append(f'regress init failed with exit {rc}: {stderr}')

    command_budgets = runtime_contract.get('commands', {})

    enforce_command_budget(
        'score',
        [str(wrkr_bin), 'score', '--state', str(state100), '--json'],
        float(command_budgets['score']['p95_ms']),
    )
    enforce_command_budget(
        'verify',
        [str(wrkr_bin), 'verify', '--chain', '--state', str(state100), '--json'],
        float(command_budgets['verify_chain']['p95_ms']),
    )
    enforce_command_budget(
        'regress run',
        [str(wrkr_bin), 'regress', 'run', '--baseline', str(baseline), '--state', str(state100), '--json'],
        float(command_budgets['regress_run']['p95_ms']),
    )
finally:
    shutil.rmtree(tmpdir)

if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(1)

print('benchmark and runtime budgets: pass')
PY
