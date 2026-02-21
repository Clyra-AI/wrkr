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
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index] * 1000.0


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

    score_runs = []
    for _ in range(5):
        rc, duration, stderr = timed_run([str(wrkr_bin), 'score', '--state', str(state100), '--json'])
        if rc != 0:
            errors.append(f'score command failed with exit {rc}: {stderr}')
            break
        score_runs.append(duration)
    if score_runs:
        limit = float(command_budgets['score']['p95_ms'])
        measured = p95_ms(score_runs)
        if measured > limit:
            errors.append(f'score p95 {measured:.2f}ms exceeds budget {limit:.2f}ms')

    verify_runs = []
    for _ in range(5):
        rc, duration, stderr = timed_run([str(wrkr_bin), 'verify', '--chain', '--state', str(state100), '--json'])
        if rc != 0:
            errors.append(f'verify command failed with exit {rc}: {stderr}')
            break
        verify_runs.append(duration)
    if verify_runs:
        limit = float(command_budgets['verify_chain']['p95_ms'])
        measured = p95_ms(verify_runs)
        if measured > limit:
            errors.append(f'verify p95 {measured:.2f}ms exceeds budget {limit:.2f}ms')

    regress_runs = []
    for _ in range(5):
        rc, duration, stderr = timed_run([str(wrkr_bin), 'regress', 'run', '--baseline', str(baseline), '--state', str(state100), '--json'])
        if rc != 0:
            errors.append(f'regress run failed with exit {rc}: {stderr}')
            break
        regress_runs.append(duration)
    if regress_runs:
        limit = float(command_budgets['regress_run']['p95_ms'])
        measured = p95_ms(regress_runs)
        if measured > limit:
            errors.append(f'regress run p95 {measured:.2f}ms exceeds budget {limit:.2f}ms')
finally:
    shutil.rmtree(tmpdir)

if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(1)

print('benchmark and runtime budgets: pass')
PY
