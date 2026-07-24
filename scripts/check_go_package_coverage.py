#!/usr/bin/env python3
"""Enforce per-package Go coverage or an explicit expiring non-regression floor."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys
from typing import Any


PACKAGE_RE = re.compile(r"(github\.com/Clyra-AI/wrkr/\S+)")
COVERAGE_RE = re.compile(r"coverage:\s*([0-9]+(?:\.[0-9]+)?)%\s+of\s+statements")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("go_test_output", type=Path)
    parser.add_argument("minimum_percent", type=float)
    parser.add_argument("exceptions", type=Path)
    return parser.parse_args()


def load_governed_exceptions(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    required = ("owner", "reason", "expires_on", "follow_up", "compensating_validation")
    missing = [key for key in required if not payload.get(key)]
    if missing:
        raise ValueError(f"coverage exception metadata missing: {', '.join(missing)}")
    expires_on = dt.date.fromisoformat(str(payload["expires_on"]))
    if expires_on < dt.datetime.now(dt.timezone.utc).date():
        raise ValueError(f"coverage exceptions expired on {expires_on.isoformat()}")
    baselines = payload.get("package_baselines")
    if not isinstance(baselines, dict):
        raise ValueError("coverage exceptions must contain package_baselines")
    return payload


def parse_package_coverage(path: Path) -> dict[str, float]:
    packages: dict[str, float] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        package_match = PACKAGE_RE.search(raw)
        if package_match is None:
            continue
        package = package_match.group(1)
        coverage_match = COVERAGE_RE.search(raw)
        if coverage_match is not None:
            packages[package] = float(coverage_match.group(1))
        elif "[no test files]" in raw:
            packages[package] = 0.0
    if not packages:
        raise ValueError("Go test output contained no first-party package coverage rows")
    return packages


def main() -> int:
    args = parse_args()
    try:
        packages = parse_package_coverage(args.go_test_output)
        governed = load_governed_exceptions(args.exceptions)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"per-package coverage gate error: {exc}", file=sys.stderr)
        return 3

    baselines = governed["package_baselines"]
    failures: list[str] = []
    governed_count = 0
    for package in sorted(set(baselines) - set(packages)):
        failures.append(f"{package}: governed baseline is stale because the package was not measured")
    for package in sorted(packages):
        percent = packages[package]
        floor = baselines.get(package)
        if percent + 1e-9 >= args.minimum_percent:
            if floor is not None:
                failures.append(
                    f"{package}: governed baseline is stale because coverage={percent:.1f}% meets target"
                )
            continue
        if not isinstance(floor, (int, float)):
            failures.append(
                f"{package}: coverage={percent:.1f}% target={args.minimum_percent:.1f}% exception=missing"
            )
            continue
        if float(floor) < 0 or float(floor) >= args.minimum_percent:
            failures.append(f"{package}: invalid governed_floor={float(floor):.1f}%")
            continue
        governed_count += 1
        if percent + 0.11 < float(floor):
            failures.append(
                f"{package}: coverage={percent:.1f}% governed_floor={float(floor):.1f}%"
            )

    if failures:
        print("per-package coverage gate: fail", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 3

    print(
        "per-package coverage gate: pass "
        f"packages={len(packages)} target={args.minimum_percent:.1f}% "
        f"governed_exceptions={governed_count} expires_on={governed['expires_on']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
