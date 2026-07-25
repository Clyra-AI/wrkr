#!/usr/bin/env python3
"""Fail closed when aggregate Go statement coverage misses its governed floor."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import sys
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverprofile", type=Path)
    parser.add_argument("minimum_percent", type=float)
    parser.add_argument("--include-prefix", action="append", default=[])
    parser.add_argument("--exceptions", type=Path)
    parser.add_argument("--scope", default="go_core_and_command_packages")
    return parser.parse_args()


def load_governed_exceptions(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    required = ("owner", "reason", "expires_on", "follow_up", "compensating_validation")
    missing = [key for key in required if not payload.get(key)]
    if missing:
        raise ValueError(f"coverage exception metadata missing: {', '.join(missing)}")
    expires_on = dt.date.fromisoformat(str(payload["expires_on"]))
    if expires_on < dt.datetime.now(dt.timezone.utc).date():
        raise ValueError(f"coverage exceptions expired on {expires_on.isoformat()}")
    return payload


def aggregate_coverage(path: Path, prefixes: list[str]) -> tuple[int, int, float]:
    total = 0
    covered = 0
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("mode:"):
            continue
        try:
            location, statements_raw, count_raw = line.rsplit(" ", 2)
            source_path = location.split(":", 1)[0]
            statements = int(statements_raw)
            count = int(count_raw)
        except (ValueError, IndexError) as exc:
            raise ValueError(f"{path}:{line_number}: malformed coverprofile row") from exc
        if prefixes and not any(source_path.startswith(prefix) for prefix in prefixes):
            continue
        total += statements
        if count > 0:
            covered += statements
    if total == 0:
        raise ValueError("coverage profile contained no statements in the selected scope")
    return covered, total, covered * 100.0 / total


def main() -> int:
    args = parse_args()
    try:
        covered, total, percent = aggregate_coverage(args.coverprofile, args.include_prefix)
        governed = load_governed_exceptions(args.exceptions)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"coverage gate error: {exc}", file=sys.stderr)
        return 3

    scope_exceptions = governed.get("aggregate_scopes", {})
    exception = scope_exceptions.get(args.scope) if isinstance(scope_exceptions, dict) else None
    if percent + 1e-9 >= args.minimum_percent:
        if exception is not None:
            print(
                f"aggregate coverage gate: fail scope={args.scope} "
                "governed exception is stale because the target is met",
                file=sys.stderr,
            )
            return 3
        print(
            f"aggregate coverage gate: pass scope={args.scope} "
            f"coverage={percent:.2f}% threshold={args.minimum_percent:.2f}% "
            f"covered_statements={covered} total_statements={total}"
        )
        return 0

    if not isinstance(exception, dict):
        print(
            f"aggregate coverage gate: fail scope={args.scope} "
            f"coverage={percent:.2f}% threshold={args.minimum_percent:.2f}% "
            "exception=missing",
            file=sys.stderr,
        )
        return 3
    floor = exception.get("minimum_percent")
    if not isinstance(floor, (int, float)):
        print(f"aggregate coverage gate: fail scope={args.scope} exception floor missing", file=sys.stderr)
        return 3
    if float(floor) < 0 or float(floor) >= args.minimum_percent:
        print(
            f"aggregate coverage gate: fail scope={args.scope} "
            f"invalid governed_floor={float(floor):.2f}%",
            file=sys.stderr,
        )
        return 3
    if percent + 0.05 < float(floor):
        print(
            f"aggregate coverage gate: fail scope={args.scope} "
            f"coverage={percent:.2f}% governed_floor={float(floor):.2f}%",
            file=sys.stderr,
        )
        return 3
    print(
        f"aggregate coverage gate: pass-with-governed-exception scope={args.scope} "
        f"coverage={percent:.2f}% target={args.minimum_percent:.2f}% "
        f"governed_floor={float(floor):.2f}% expires_on={governed['expires_on']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
