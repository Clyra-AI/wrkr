#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from release_changelog import validate_release_changelog


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate that CHANGELOG.md is finalized for a concrete release "
            "tag and that the versioned section matches the expected semver bump."
        )
    )
    parser.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parents[1],
        help="repository root to inspect (default: script parent repo root)",
    )
    parser.add_argument(
        "--release-version",
        required=True,
        help="release version to validate as vX.Y.Z",
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
        payload = validate_release_changelog(repo_root, args.release_version)
    except (RuntimeError, ValueError) as err:
        print(f"validate_release_changelog: {err}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"{payload['version']} ({payload['bump']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
