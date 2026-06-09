#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any


ALLOWED_VIRTUAL_PREFIXES = ("virtual:", "future:", "generated:")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate profile path references against the active repository layout."
    )
    parser.add_argument("--repo-root", default=".", help="active repository root")
    parser.add_argument("--profile", help="profile id from factory/profiles")
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    return parser.parse_args()


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_yaml_lite(text: str) -> dict[str, Any]:
    lines = text.splitlines()

    def skip(index: int) -> int:
        while index < len(lines):
            stripped = lines[index].strip()
            if stripped and not stripped.startswith("#"):
                break
            index += 1
        return index

    def parse_inline_map_item(value: str) -> dict[str, Any] | None:
        if strip_quotes(value).startswith(ALLOWED_VIRTUAL_PREFIXES):
            return None
        key, sep, rest = value.partition(":")
        if not sep or not key.strip():
            return None
        return {key.strip(): strip_quotes(rest.strip()) if rest.strip() else {}}

    def parse_list(index: int, indent: int) -> tuple[list[Any], int]:
        items: list[Any] = []
        while True:
            index = skip(index)
            if index >= len(lines):
                break
            line = lines[index]
            current_indent = indentation(line)
            stripped = line.strip()
            if current_indent < indent or not stripped.startswith("- "):
                break
            if current_indent != indent:
                raise ValueError(f"unsupported list indentation at line {index + 1}")
            raw_item = stripped[2:].strip()
            inline_map = parse_inline_map_item(raw_item)
            index += 1
            next_index = skip(index)
            if inline_map is not None:
                if next_index < len(lines) and indentation(lines[next_index]) > current_indent:
                    nested, index = parse_map(next_index, current_indent + 2)
                    inline_map.update(nested)
                items.append(inline_map)
                continue

            items.append(strip_quotes(raw_item))
        return items, index

    def parse_map(index: int, indent: int) -> tuple[dict[str, Any], int]:
        out: dict[str, Any] = {}
        while True:
            index = skip(index)
            if index >= len(lines):
                break
            line = lines[index]
            current_indent = indentation(line)
            stripped = line.strip()
            if current_indent < indent:
                break
            if current_indent != indent:
                raise ValueError(f"unsupported map indentation at line {index + 1}")
            if stripped.startswith("- "):
                raise ValueError(f"unexpected list item at line {index + 1}")
            key, sep, rest = stripped.partition(":")
            if not sep:
                raise ValueError(f"expected key/value pair at line {index + 1}")
            rest = rest.strip()
            if rest:
                out[key] = strip_quotes(rest)
                index += 1
                continue

            next_index = skip(index + 1)
            if next_index >= len(lines) or indentation(lines[next_index]) <= current_indent:
                out[key] = {}
                index = next_index
                continue
            if lines[next_index].strip().startswith("- "):
                list_value, index = parse_list(next_index, current_indent + 2)
                out[key] = list_value
                continue
            map_value, index = parse_map(next_index, current_indent + 2)
            out[key] = map_value
        return out, index

    parsed, _ = parse_map(0, 0)
    return parsed


def resolve_executable(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise ValueError(f"required executable not found on PATH: {name}")
    return resolved


def git_remote(repo_root: Path) -> str:
    try:
        git_executable = resolve_executable("git")
        return subprocess.check_output(  # nosec B603
            [git_executable, "-C", str(repo_root), "remote", "get-url", "origin"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return ""


def resolve_profile_path(repo_root: Path, explicit_profile: str | None) -> tuple[str, Path, dict[str, Any]]:
    profiles_dir = repo_root / "factory" / "profiles"
    if not profiles_dir.exists():
        raise ValueError(f"missing profiles directory: {profiles_dir}")

    parsed_profiles: list[tuple[str, Path, dict[str, Any]]] = []
    for profile_path in sorted(profiles_dir.glob("*.yaml")):
        parsed_profiles.append((profile_path.stem, profile_path, parse_yaml_lite(profile_path.read_text(encoding="utf-8"))))

    if explicit_profile:
        for profile_id, profile_path, parsed in parsed_profiles:
            if profile_id == explicit_profile:
                return profile_id, profile_path, parsed
        raise ValueError(f"unknown profile {explicit_profile!r}")

    remote = git_remote(repo_root)
    for profile_id, profile_path, parsed in parsed_profiles:
        match = parsed.get("match", {})
        if not isinstance(match, dict):
            continue
        directory_names = match.get("directory_names", [])
        remotes = match.get("remotes", [])
        if isinstance(directory_names, list) and repo_root.name in directory_names:
            return profile_id, profile_path, parsed
        if isinstance(remotes, list) and any(str(remote_name) in remote for remote_name in remotes):
            return profile_id, profile_path, parsed

    raise ValueError("could not infer profile from repo directory name or origin remote")


def ensure_string_map(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a map")
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(item, str):
            raise ValueError(f"{label}.{key} must be a string path")
        out[str(key)] = item
    return out


def ensure_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{label} entries must be string paths")
        out.append(item)
    return out


def classify_reference(value: str) -> tuple[str, str]:
    stripped = value.strip()
    for prefix in ALLOWED_VIRTUAL_PREFIXES:
        if stripped.startswith(prefix):
            return "virtual", stripped[len(prefix) :]
    if any(char in stripped for char in "*?["):
        return "glob", stripped
    return "path", stripped


def validate_reference(
    repo_root: Path,
    label: str,
    raw_value: str,
    failures: list[str],
    checked: list[dict[str, str]],
) -> None:
    kind, value = classify_reference(raw_value)
    if kind == "virtual":
        checked.append({"label": label, "value": raw_value, "kind": "virtual"})
        return

    if kind == "glob":
        if not any(repo_root.glob(value)):
            failures.append(f"{label}: glob did not match any paths: {raw_value}")
            return
        checked.append({"label": label, "value": raw_value, "kind": "glob"})
        return

    target = repo_root / value
    if not target.exists():
        failures.append(f"{label}: missing path {raw_value}")
        return
    checked.append({"label": label, "value": raw_value, "kind": "path"})


def validate_profile(repo_root: Path, profile_id: str, profile_path: Path, parsed: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    checked: list[dict[str, str]] = []

    standards = ensure_string_map(parsed.get("standards"), "standards")
    docs = parsed.get("docs", {})
    if not isinstance(docs, dict):
        raise ValueError("docs must be a map")
    user_facing_paths = ensure_string_list(docs.get("user_facing_paths"), "docs.user_facing_paths")

    code_review = parsed.get("code_review", {})
    if not isinstance(code_review, dict):
        raise ValueError("code_review must be a map")
    high_risk_surfaces = ensure_string_list(code_review.get("high_risk_surfaces"), "code_review.high_risk_surfaces")

    for key, value in standards.items():
        validate_reference(repo_root, f"standards.{key}", value, failures, checked)
    for index, value in enumerate(user_facing_paths):
        validate_reference(repo_root, f"docs.user_facing_paths[{index}]", value, failures, checked)
    for index, value in enumerate(high_risk_surfaces):
        validate_reference(repo_root, f"code_review.high_risk_surfaces[{index}]", value, failures, checked)

    return {
        "status": "pass" if not failures else "fail",
        "profile": profile_id,
        "profile_path": str(profile_path),
        "checked": checked,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    try:
        profile_id, profile_path, parsed = resolve_profile_path(repo_root, args.profile)
        result = validate_profile(repo_root, profile_id, profile_path, parsed)
    except (OSError, ValueError) as exc:
        result = {
            "status": "fail",
            "failures": [str(exc)],
        }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "pass":
            print(f"profile validation passed for {result['profile']}")
        else:
            print("profile validation failed", file=sys.stderr)
            for failure in result.get("failures", []):
                print(f"- {failure}", file=sys.stderr)

    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
