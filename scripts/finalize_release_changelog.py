#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from release_changelog import finalize_changelog


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Promote CHANGELOG.md Unreleased entries into a versioned release "
            "section and reset Unreleased for the next release cycle."
        )
    )
    parser.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parents[1],
        help="repository root to inspect (default: script parent repo root)",
    )
    parser.add_argument(
        "--release-version",
        help="explicit release version to validate and finalize as vX.Y.Z",
    )
    parser.add_argument(
        "--release-date",
        help="explicit ISO date for the versioned changelog section (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a JSON object instead of a short human-readable summary",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()

    try:
        payload = finalize_changelog(repo_root, args.release_version, args.release_date)
    except (RuntimeError, ValueError) as err:
        print(f"finalize_release_changelog: {err}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"{payload['version']} ({payload['bump']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
