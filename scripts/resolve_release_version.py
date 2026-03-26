#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec B404
import sys
from pathlib import Path


SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
UNRELEASED_RE = re.compile(r"^##\s+\[Unreleased\]\s*$", re.IGNORECASE)
SECTION_RE = re.compile(r"^###\s+(.+?)\s*$")
NEXT_TOP_LEVEL_RE = re.compile(r"^##\s+\[")
ENTRY_RE = re.compile(r"^[-*]\s+(.*\S)\s*$")
NONE_RE = re.compile(r"^\(?none yet\)?\.?$", re.IGNORECASE)
BREAKING_RE = re.compile(r"\bBREAKING(?:\s+CHANGE)?\b\s*:?", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve the next Wrkr release version deterministically from an "
            "explicit version or CHANGELOG.md Unreleased entries."
        )
    )
    parser.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parents[1],
        help="repository root to inspect (default: script parent repo root)",
    )
    parser.add_argument(
        "--release-version",
        help="explicit release version to normalize to vX.Y.Z",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a JSON object instead of the resolved version only",
    )
    return parser.parse_args()


def normalize_version(value: str) -> tuple[str, tuple[int, int, int]]:
    match = SEMVER_RE.fullmatch(value.strip())
    if not match:
        raise ValueError(f"invalid semantic version {value!r}; expected vX.Y.Z")
    major, minor, patch = (int(part) for part in match.groups())
    return f"v{major}.{minor}.{patch}", (major, minor, patch)


def bump_version(version: str, bump: str) -> str:
    normalized, (major, minor, patch) = normalize_version(version)
    _ = normalized
    if bump == "major":
        return f"v{major + 1}.0.0"
    if bump == "minor":
        return f"v{major}.{minor + 1}.0"
    if bump == "patch":
        return f"v{major}.{minor}.{patch + 1}"
    raise ValueError(f"unsupported bump kind: {bump}")


def run_git(repo_root: Path, *args: str) -> str:
    cmd = ["git", "-C", str(repo_root), *args]
    # Local trusted git invocation with fixed argv; shell is never used.
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec B603
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "git command failed"
        raise RuntimeError(f"{' '.join(cmd)}: {detail}")
    return proc.stdout.strip()


def latest_semver_tag(repo_root: Path) -> str:
    output = run_git(repo_root, "tag", "--list", "v[0-9]*.[0-9]*.[0-9]*", "--sort=-version:refname")
    lines = output.splitlines()
    if not lines:
        return ""
    return lines[0]


def has_changes_since(repo_root: Path, ref: str) -> bool:
    # Local trusted git invocation with fixed argv; shell is never used.
    proc = subprocess.run(  # nosec B603,B607
        ["git", "-C", str(repo_root), "diff", "--quiet", f"{ref}..HEAD", "--"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return False
    if proc.returncode == 1:
        return True
    detail = proc.stderr.strip() or proc.stdout.strip() or "git diff failed"
    raise RuntimeError(f"git diff --quiet {ref}..HEAD --: {detail}")


def parse_unreleased_entries(changelog_path: Path) -> list[dict[str, str]]:
    if not changelog_path.is_file():
        raise RuntimeError(f"missing changelog: {changelog_path}")

    entries: list[dict[str, str]] = []
    in_unreleased = False
    current_section = ""

    for raw_line in changelog_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not in_unreleased:
            if UNRELEASED_RE.match(line):
                in_unreleased = True
            continue
        if NEXT_TOP_LEVEL_RE.match(line):
            break
        section_match = SECTION_RE.match(line)
        if section_match:
            current_section = section_match.group(1).strip().lower()
            continue
        entry_match = ENTRY_RE.match(line)
        if not entry_match:
            continue
        entry = entry_match.group(1).strip()
        if not entry or NONE_RE.match(entry):
            continue
        entries.append({"section": current_section, "text": entry})

    if not in_unreleased:
        raise RuntimeError(f"missing ## [Unreleased] section in {changelog_path}")
    return entries


def classify_bump(entries: list[dict[str, str]]) -> tuple[str, str]:
    for bump in ("major", "minor", "patch"):
        marker = f"[semver:{bump}]"
        if any(marker in entry["text"].lower() for entry in entries):
            return bump, f"explicit {marker} marker in CHANGELOG.md Unreleased"

    if any(entry["section"] == "removed" for entry in entries):
        return "major", "CHANGELOG.md Unreleased has Removed entries"

    if any(BREAKING_RE.search(entry["text"]) for entry in entries):
        return "major", "CHANGELOG.md Unreleased contains BREAKING markers"

    if any(entry["section"] == "added" for entry in entries):
        return "minor", "CHANGELOG.md Unreleased has Added entries"

    patch_sections = {"changed", "fixed", "security", "deprecated"}
    if any(entry["section"] in patch_sections for entry in entries):
        return "patch", "CHANGELOG.md Unreleased has patch-level Changed/Fixed/Security/Deprecated entries"

    raise RuntimeError(
        "could not infer semver bump from CHANGELOG.md Unreleased; "
        "add releasable entries or an explicit [semver:major|minor|patch] marker"
    )


def emit(payload: dict[str, str], as_json: bool) -> int:
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(payload["version"])
    return 0


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()

    try:
        if args.release_version:
            version, _ = normalize_version(args.release_version)
            return emit(
                {
                    "version": version,
                    "bump": "explicit",
                    "base_tag": "",
                    "source": "argument",
                    "reason": "explicit release version provided",
                },
                args.json,
            )

        latest_tag = latest_semver_tag(repo_root)
        if not latest_tag:
            return emit(
                {
                    "version": "v1.0.0",
                    "bump": "bootstrap",
                    "base_tag": "",
                    "source": "default",
                    "reason": "no existing semantic version tags found",
                },
                args.json,
            )

        if not has_changes_since(repo_root, latest_tag):
            raise RuntimeError(f"no changes found since {latest_tag}; refusing to invent a new release version")

        entries = parse_unreleased_entries(repo_root / "CHANGELOG.md")
        bump, reason = classify_bump(entries)
        version = bump_version(latest_tag, bump)
        return emit(
            {
                "version": version,
                "bump": bump,
                "base_tag": latest_tag,
                "source": "changelog",
                "reason": reason,
            },
            args.json,
        )
    except (RuntimeError, ValueError) as err:
        print(f"resolve_release_version: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
