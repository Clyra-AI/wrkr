#!/usr/bin/env python3

from __future__ import annotations

import re
import subprocess  # nosec B404
from datetime import date
from pathlib import Path
from typing import cast


SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
UNRELEASED_RE = re.compile(r"^##\s+\[Unreleased\]\s*$", re.IGNORECASE)
VERSION_SECTION_RE = re.compile(r"^##\s+\[(v?\d+\.\d+\.\d+)\](?:\s+-\s+(\d{4}-\d{2}-\d{2}))?\s*$")
MAINTENANCE_RE = re.compile(r"^##\s+Changelog maintenance process\s*$", re.IGNORECASE)
NEXT_TOP_LEVEL_RE = re.compile(r"^##\s+")
SECTION_RE = re.compile(r"^###\s+(.+?)\s*$")
ENTRY_RE = re.compile(r"^[-*]\s+(.*\S)\s*$")
NONE_RE = re.compile(r"^\(?none yet\)?\.?$", re.IGNORECASE)
BREAKING_RE = re.compile(r"\bBREAKING(?:\s+CHANGE)?\b\s*:?", re.IGNORECASE)
SEMVER_MARKER_RE = re.compile(r"\[semver:(major|minor|patch)\]", re.IGNORECASE)
RELEASE_SEMVER_RE = re.compile(r"^<!--\s*release-semver:\s*(bootstrap|major|minor|patch)\s*-->\s*$", re.IGNORECASE)

SECTION_ORDER = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
SECTION_NAME_MAP = {section.lower(): section for section in SECTION_ORDER}


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
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec B603
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "git command failed"
        raise RuntimeError(f"{' '.join(cmd)}: {detail}")
    return proc.stdout.strip()


def latest_semver_tag(repo_root: Path, exclude: set[str] | None = None) -> str:
    excluded = exclude or set()
    output = run_git(repo_root, "tag", "--merged", "HEAD", "--sort=-version:refname")
    for line in output.splitlines():
        candidate = line.strip()
        if candidate in excluded:
            continue
        if SEMVER_RE.fullmatch(candidate):
            return candidate
    return ""


def has_changes_since(repo_root: Path, ref: str) -> bool:
    output = run_git(repo_root, "diff", "--name-only", f"{ref}..HEAD", "--")
    return bool(output.splitlines())


def read_lines(changelog_path: Path) -> list[str]:
    if not changelog_path.is_file():
        raise RuntimeError(f"missing changelog: {changelog_path}")
    return changelog_path.read_text(encoding="utf-8").splitlines()


def canonical_section_name(name: str) -> str:
    stripped = name.strip()
    return SECTION_NAME_MAP.get(stripped.lower(), stripped)


def find_block(lines: list[str], predicate) -> tuple[int, int]:
    start = -1
    for idx, raw_line in enumerate(lines):
        if predicate(raw_line.strip()):
            start = idx
            break
    if start < 0:
        raise RuntimeError("requested changelog block was not found")
    end = len(lines)
    for idx in range(start + 1, len(lines)):
        if NEXT_TOP_LEVEL_RE.match(lines[idx].strip()):
            end = idx
            break
    return start, end


def find_unreleased_block(lines: list[str]) -> tuple[int, int]:
    try:
        return find_block(lines, lambda line: bool(UNRELEASED_RE.match(line)))
    except RuntimeError as err:
        raise RuntimeError("missing ## [Unreleased] section in CHANGELOG.md") from err


def find_maintenance_block(lines: list[str]) -> tuple[int, int] | None:
    try:
        return find_block(lines, lambda line: bool(MAINTENANCE_RE.match(line)))
    except RuntimeError:
        return None


def find_version_block(lines: list[str], version: str) -> tuple[int, int] | None:
    normalized, _ = normalize_version(version)
    for idx, raw_line in enumerate(lines):
        match = VERSION_SECTION_RE.match(raw_line.strip())
        if not match:
            continue
        candidate, _ = normalize_version(match.group(1))
        if candidate != normalized:
            continue
        end = len(lines)
        for block_end in range(idx + 1, len(lines)):
            if NEXT_TOP_LEVEL_RE.match(lines[block_end].strip()):
                end = block_end
                break
        return idx, end
    return None


def find_first_version_start(lines: list[str]) -> int | None:
    for idx, raw_line in enumerate(lines):
        if VERSION_SECTION_RE.match(raw_line.strip()):
            return idx
    return None


def parse_block(lines: list[str], start: int, end: int) -> dict[str, object]:
    entries: list[dict[str, str]] = []
    sections_present: list[str] = []
    unknown_sections_with_entries: list[str] = []
    semver_hint = ""
    current_section = ""

    for raw_line in lines[start + 1 : end]:
        line = raw_line.strip()
        if not line:
            continue
        release_semver_match = RELEASE_SEMVER_RE.match(line)
        if release_semver_match:
            semver_hint = release_semver_match.group(1).lower()
            continue
        section_match = SECTION_RE.match(line)
        if section_match:
            current_section = canonical_section_name(section_match.group(1))
            if current_section not in sections_present:
                sections_present.append(current_section)
            continue
        entry_match = ENTRY_RE.match(line)
        if not entry_match:
            continue
        entry = entry_match.group(1).strip()
        if not entry or NONE_RE.match(entry):
            continue
        entries.append({"section": current_section.lower(), "text": entry})
        if current_section and current_section not in SECTION_NAME_MAP.values() and current_section not in unknown_sections_with_entries:
            unknown_sections_with_entries.append(current_section)

    return {
        "entries": entries,
        "sections_present": sections_present,
        "unknown_sections_with_entries": unknown_sections_with_entries,
        "semver_hint": semver_hint,
    }


def parse_unreleased_block(changelog_path: Path) -> dict[str, object]:
    lines = read_lines(changelog_path)
    start, end = find_unreleased_block(lines)
    return parse_block(lines, start, end)


def parse_versioned_block(changelog_path: Path, version: str) -> dict[str, object]:
    lines = read_lines(changelog_path)
    block = find_version_block(lines, version)
    if block is None:
        raise RuntimeError(f"missing versioned changelog section for {version}")
    start, end = block
    parsed = parse_block(lines, start, end)
    header = lines[start].strip()
    match = VERSION_SECTION_RE.match(header)
    if match is None:
        raise RuntimeError(f"invalid versioned changelog header for {version}")
    parsed["release_date"] = match.group(2) or ""
    return parsed


def classify_bump(entries: list[dict[str, str]], semver_hint: str = "") -> tuple[str, str]:
    if semver_hint:
        if semver_hint == "bootstrap":
            return "bootstrap", "explicit release-semver bootstrap marker"
        return semver_hint, f"explicit release-semver {semver_hint} marker"

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


def sanitize_release_entry(text: str) -> str:
    stripped = SEMVER_MARKER_RE.sub("", text).strip()
    return re.sub(r"\s{2,}", " ", stripped)


def group_release_entries(entries: list[dict[str, str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {section: [] for section in SECTION_ORDER}
    for entry in entries:
        section = SECTION_NAME_MAP.get(entry["section"], canonical_section_name(entry["section"]))
        cleaned = sanitize_release_entry(entry["text"])
        if cleaned:
            grouped.setdefault(section, []).append(cleaned)
    return grouped


def render_unreleased_block() -> list[str]:
    lines = ["## [Unreleased]", ""]
    for section in SECTION_ORDER:
        lines.extend([f"### {section}", "", "- (none yet)", ""])
    return lines


def render_release_block(version: str, release_date: str, bump: str, grouped_entries: dict[str, list[str]]) -> list[str]:
    lines = [f"## [{version}] - {release_date}", f"<!-- release-semver: {bump} -->", ""]
    for section in SECTION_ORDER:
        section_entries = grouped_entries.get(section, [])
        if not section_entries:
            continue
        lines.extend([f"### {section}", ""])
        for entry in section_entries:
            lines.append(f"- {entry}")
        lines.append("")
    return lines


def stitch_segments(*segments: list[str]) -> str:
    merged: list[str] = []
    for segment in segments:
        if not segment:
            continue
        chunk = list(segment)
        while chunk and not chunk[0].strip() and (not merged or not merged[-1].strip()):
            chunk.pop(0)
        if merged and merged[-1].strip() and chunk and chunk[0].strip():
            merged.append("")
        merged.extend(chunk)
    while merged and not merged[-1].strip():
        merged.pop()
    return "\n".join(merged) + "\n"


def resolve_release_plan(repo_root: Path, release_version: str | None = None) -> dict[str, str]:
    changelog_path = repo_root / "CHANGELOG.md"
    latest_tag = latest_semver_tag(repo_root)

    if release_version:
        version, _ = normalize_version(release_version)
        if not latest_tag:
            if version != "v1.0.0":
                raise RuntimeError(
                    f"explicit bootstrap release version {version} does not match the required initial release v1.0.0"
                )
            return {
                "version": version,
                "bump": "bootstrap",
                "base_tag": "",
                "source": "argument",
                "reason": "explicit release version matches bootstrap default",
            }

        if not has_changes_since(repo_root, latest_tag):
            raise RuntimeError(f"no changes found since {latest_tag}; refusing to invent a new release version")

        entries = cast(list[dict[str, str]], parse_unreleased_block(changelog_path)["entries"])
        bump, reason = classify_bump(entries)
        expected_version = bump_version(latest_tag, bump)
        if version != expected_version:
            raise RuntimeError(
                f"explicit release version {version} does not match changelog-derived {expected_version} from {latest_tag}"
            )
        return {
            "version": version,
            "bump": bump,
            "base_tag": latest_tag,
            "source": "argument",
            "reason": f"explicit release version matches changelog-derived {bump} bump ({reason})",
        }

    if not latest_tag:
        return {
            "version": "v1.0.0",
            "bump": "bootstrap",
            "base_tag": "",
            "source": "default",
            "reason": "no existing semantic version tags found",
        }

    if not has_changes_since(repo_root, latest_tag):
        raise RuntimeError(f"no changes found since {latest_tag}; refusing to invent a new release version")

    entries = cast(list[dict[str, str]], parse_unreleased_block(changelog_path)["entries"])
    bump, reason = classify_bump(entries)
    version = bump_version(latest_tag, bump)
    return {
        "version": version,
        "bump": bump,
        "base_tag": latest_tag,
        "source": "changelog",
        "reason": reason,
    }


def finalize_changelog(repo_root: Path, release_version: str | None = None, release_date: str | None = None) -> dict[str, str]:
    plan = resolve_release_plan(repo_root, release_version)
    changelog_path = repo_root / "CHANGELOG.md"
    lines = read_lines(changelog_path)
    version = plan["version"]

    if find_version_block(lines, version) is not None:
        raise RuntimeError(f"CHANGELOG.md already contains a versioned section for {version}")

    unreleased_start, unreleased_end = find_unreleased_block(lines)
    unreleased = parse_block(lines, unreleased_start, unreleased_end)
    unreleased_entries = cast(list[dict[str, str]], unreleased["entries"])
    unknown_sections = cast(list[str], unreleased["unknown_sections_with_entries"])
    if not unreleased_entries:
        raise RuntimeError("CHANGELOG.md Unreleased has no releasable entries to promote")
    if unknown_sections:
        raise RuntimeError(
            "CHANGELOG.md Unreleased has releasable entries under unknown sections: "
            + ", ".join(unknown_sections)
        )

    maintenance_block = find_maintenance_block(lines)
    first_version_start = find_first_version_start(lines)
    if first_version_start is not None:
        insertion_point = first_version_start
    elif maintenance_block is not None:
        insertion_point = maintenance_block[1]
    else:
        insertion_point = unreleased_end

    effective_release_date = (release_date or date.today().isoformat()).strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", effective_release_date):
        raise RuntimeError(f"invalid release date {effective_release_date!r}; expected YYYY-MM-DD")

    rendered = stitch_segments(
        lines[:unreleased_start],
        render_unreleased_block(),
        lines[unreleased_end:insertion_point],
        render_release_block(version, effective_release_date, plan["bump"], group_release_entries(unreleased_entries)),
        lines[insertion_point:],
    )
    changelog_path.write_text(rendered, encoding="utf-8")

    payload = dict(plan)
    payload["release_date"] = effective_release_date
    payload["source"] = "finalized_changelog"
    return payload


def validate_release_changelog(repo_root: Path, release_version: str) -> dict[str, str]:
    normalized_version, _ = normalize_version(release_version)
    changelog_path = repo_root / "CHANGELOG.md"

    released = parse_versioned_block(changelog_path, normalized_version)
    release_entries = cast(list[dict[str, str]], released["entries"])
    unknown_sections = cast(list[str], released["unknown_sections_with_entries"])
    if not release_entries:
        raise RuntimeError(f"versioned changelog section for {normalized_version} has no releasable entries")
    if unknown_sections:
        raise RuntimeError(
            f"versioned changelog section for {normalized_version} has releasable entries under unknown sections: "
            + ", ".join(unknown_sections)
        )

    release_date = str(released.get("release_date", "")).strip()
    if not release_date:
        raise RuntimeError(f"versioned changelog section for {normalized_version} is missing an ISO release date")

    bump, reason = classify_bump(release_entries, str(released["semver_hint"]))
    base_tag = latest_semver_tag(repo_root, exclude={normalized_version})

    if base_tag:
        if bump == "bootstrap":
            raise RuntimeError(f"release section for {normalized_version} cannot declare bootstrap with previous tag {base_tag}")
        expected = bump_version(base_tag, bump)
        if expected != normalized_version:
            raise RuntimeError(
                f"release version {normalized_version} does not match changelog-derived {expected} from {base_tag}"
            )
    else:
        if normalized_version != "v1.0.0":
            raise RuntimeError(
                f"first versioned changelog section must be v1.0.0 when no previous semantic version tags exist, got {normalized_version}"
            )

    unreleased = parse_unreleased_block(changelog_path)
    if unreleased["entries"]:
        raise RuntimeError("CHANGELOG.md Unreleased still contains releasable entries after release finalization")

    unreleased_sections = cast(list[str], unreleased["sections_present"])
    missing_sections = [section for section in SECTION_ORDER if section not in unreleased_sections]
    if missing_sections:
        raise RuntimeError(
            f"CHANGELOG.md Unreleased is missing canonical sections after release finalization: {', '.join(missing_sections)}"
        )

    return {
        "version": normalized_version,
        "bump": bump,
        "base_tag": base_tag,
        "release_date": release_date,
        "reason": reason,
        "source": "versioned_changelog",
        "status": "ok",
    }
