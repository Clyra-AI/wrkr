#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any


ACTIONABLE_SEVERITIES = {"moderate", "high", "critical"}
EXCEPTION_SCHEMA_ID = "wrkr.docs_site.audit_exceptions"
EXCEPTION_SCHEMA_VERSION = "1.0.0"
REQUIRED_EXCEPTION_FIELDS = [
    "package",
    "advisory",
    "severity",
    "affected_node",
    "direct_dependency",
    "current_version",
    "owner",
    "scope",
    "rationale",
    "expires_on",
    "upgrade_trigger",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate docs-site production dependency audit results against explicit exceptions."
    )
    parser.add_argument("--repo-root", default=".", help="active repository root")
    parser.add_argument(
        "--package-dir",
        default="docs-site",
        help="docs-site directory relative to repo root or absolute path",
    )
    parser.add_argument(
        "--exceptions",
        default="docs-site/security-advisory-exceptions.json",
        help="exception file path relative to repo root or absolute path",
    )
    parser.add_argument(
        "--lockfile",
        default="docs-site/package-lock.json",
        help="package lock path relative to repo root or absolute path",
    )
    parser.add_argument(
        "--audit-report",
        help="optional pre-recorded npm audit JSON file; when omitted the script runs npm audit",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    return parser.parse_args()


def resolve_path(repo_root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return repo_root / path


def advisory_id_from(via: dict[str, Any]) -> str:
    url = str(via.get("url") or "").rstrip("/")
    if "/advisories/" in url:
        return url.rsplit("/", 1)[-1]
    source = via.get("source")
    if source is None:
        return "unknown-advisory"
    return str(source)


def node_modules_chain(node: str) -> list[str]:
    parts = [part for part in node.split("/") if part]
    packages: list[str] = []
    index = 0
    while index < len(parts):
        if parts[index] != "node_modules":
            index += 1
            continue
        if index + 1 >= len(parts):
            break
        package_name = parts[index + 1]
        if package_name.startswith("@") and index + 2 < len(parts):
            package_name = f"{package_name}/{parts[index + 2]}"
            index += 1
        packages.append(package_name)
        index += 2
    return packages


def top_level_dependency_for_node(node: str) -> str:
    chain = node_modules_chain(node)
    return chain[0] if chain else ""


def lockfile_version(lockfile: dict[str, Any], package_name: str) -> str:
    packages = lockfile.get("packages")
    if not isinstance(packages, dict):
        return ""
    key = f"node_modules/{package_name}"
    entry = packages.get(key)
    if not isinstance(entry, dict):
        return ""
    version = entry.get("version")
    return str(version).strip() if version is not None else ""


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_npm_audit(package_dir: Path) -> dict[str, Any]:
    env = os.environ.copy()
    completed = subprocess.run(
        ["npm", "audit", "--omit=dev", "--json"],
        cwd=package_dir,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    stdout = completed.stdout.strip()
    if not stdout:
        stderr = completed.stderr.strip() or "npm audit did not return JSON output"
        raise ValueError(stderr)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        stderr = completed.stderr.strip()
        message = f"failed to parse npm audit JSON: {exc}"
        if stderr:
            message = f"{message}; stderr={stderr}"
        raise ValueError(message) from exc


def collect_actionable_advisories(report: dict[str, Any], lockfile: dict[str, Any]) -> list[dict[str, str]]:
    vulnerabilities = report.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise ValueError("npm audit JSON missing vulnerabilities object")

    advisories: dict[tuple[str, str, str], dict[str, str]] = {}
    for package_name, raw_details in vulnerabilities.items():
        if not isinstance(raw_details, dict):
            continue
        nodes = [node for node in raw_details.get("nodes", []) if isinstance(node, str)]
        via_entries = raw_details.get("via", [])
        if not isinstance(via_entries, list):
            continue
        for via in via_entries:
            if not isinstance(via, dict):
                continue
            severity = str(via.get("severity") or raw_details.get("severity") or "").strip().lower()
            if severity not in ACTIONABLE_SEVERITIES:
                continue
            advisory_id = advisory_id_from(via)
            for node in nodes or [""]:
                direct_dependency = top_level_dependency_for_node(node) or str(package_name)
                key = (str(package_name), advisory_id, node)
                advisories[key] = {
                    "package": str(package_name),
                    "advisory": advisory_id,
                    "severity": severity,
                    "affected_node": node,
                    "direct_dependency": direct_dependency,
                    "current_version": lockfile_version(lockfile, direct_dependency),
                    "title": str(via.get("title") or ""),
                    "url": str(via.get("url") or ""),
                    "range": str(via.get("range") or raw_details.get("range") or ""),
                }
    return sorted(
        advisories.values(),
        key=lambda item: (item["severity"], item["package"], item["advisory"], item["affected_node"]),
    )


def validate_exception_shape(raw: dict[str, Any], failures: list[str]) -> None:
    for field in REQUIRED_EXCEPTION_FIELDS:
        value = raw.get(field)
        if value is None or not str(value).strip():
            failures.append(f"exception missing required field {field!r}")
    severity = str(raw.get("severity") or "").strip().lower()
    if severity != "moderate":
        failures.append(
            f"exception {raw.get('advisory', '<unknown>')!r} must target a moderate advisory, got {severity!r}"
        )
    expires_on = str(raw.get("expires_on") or "").strip()
    if expires_on:
        try:
            expiry = date.fromisoformat(expires_on)
        except ValueError:
            failures.append(
                f"exception {raw.get('advisory', '<unknown>')!r} has invalid expires_on {expires_on!r}"
            )
            return
        if expiry < date.today():
            failures.append(
                f"exception {raw.get('advisory', '<unknown>')!r} expired on {expires_on}"
            )


def load_exceptions(path: Path, failures: list[str]) -> list[dict[str, str]]:
    payload = load_json(path)
    if payload.get("schema_id") != EXCEPTION_SCHEMA_ID:
        failures.append(f"{path}: unexpected schema_id {payload.get('schema_id')!r}")
    if payload.get("schema_version") != EXCEPTION_SCHEMA_VERSION:
        failures.append(f"{path}: unexpected schema_version {payload.get('schema_version')!r}")

    raw_exceptions = payload.get("exceptions")
    if not isinstance(raw_exceptions, list) or not raw_exceptions:
        failures.append(f"{path}: exceptions must be a non-empty list")
        return []

    normalized: list[dict[str, str]] = []
    for raw in raw_exceptions:
        if not isinstance(raw, dict):
            failures.append(f"{path}: exception entries must be objects")
            continue
        validate_exception_shape(raw, failures)
        normalized.append({key: str(raw.get(key, "")).strip() for key in REQUIRED_EXCEPTION_FIELDS})
    return normalized


def matches_exception(exception: dict[str, str], advisory: dict[str, str]) -> bool:
    return (
        exception["package"] == advisory["package"]
        and exception["advisory"] == advisory["advisory"]
        and exception["severity"] == advisory["severity"]
        and exception["affected_node"] == advisory["affected_node"]
        and exception["direct_dependency"] == advisory["direct_dependency"]
        and exception["current_version"] == advisory["current_version"]
    )


def validate_audit(
    repo_root: Path,
    package_dir: Path,
    exceptions_path: Path,
    lockfile_path: Path,
    audit_report_path: Path | None,
) -> dict[str, Any]:
    failures: list[str] = []
    if not package_dir.exists():
        failures.append(f"package directory does not exist: {package_dir}")
    if not exceptions_path.exists():
        failures.append(f"exception file does not exist: {exceptions_path}")
    if not lockfile_path.exists():
        failures.append(f"lockfile does not exist: {lockfile_path}")
    if audit_report_path is not None and not audit_report_path.exists():
        failures.append(f"audit report does not exist: {audit_report_path}")
    if failures:
        return {
            "status": "fail",
            "failures": failures,
        }

    lockfile = load_json(lockfile_path)
    exceptions = load_exceptions(exceptions_path, failures)
    if audit_report_path is not None:
        audit_report = load_json(audit_report_path)
    else:
        try:
            audit_report = run_npm_audit(package_dir)
        except ValueError as exc:
            failures.append(str(exc))
            return {
                "status": "fail",
                "failures": failures,
            }

    actionable_advisories = collect_actionable_advisories(audit_report, lockfile)
    matched_indices: set[int] = set()
    matched_exceptions: list[dict[str, str]] = []
    unmatched_advisories: list[dict[str, str]] = []

    for advisory in actionable_advisories:
        if advisory["severity"] in {"high", "critical"}:
            failures.append(
                f"{advisory['severity']} advisory {advisory['advisory']} on {advisory['package']} cannot be excepted"
            )
            continue

        match_index = None
        for index, exception in enumerate(exceptions):
            if matches_exception(exception, advisory):
                match_index = index
                break
        if match_index is None:
            unmatched_advisories.append(advisory)
            failures.append(
                "moderate advisory missing matching exception: "
                f"{advisory['advisory']} package={advisory['package']} "
                f"node={advisory['affected_node']} direct_dependency={advisory['direct_dependency']} "
                f"current_version={advisory['current_version']}"
            )
            continue
        matched_indices.add(match_index)
        matched_exceptions.append(exceptions[match_index])

    stale_exceptions: list[dict[str, str]] = []
    for index, exception in enumerate(exceptions):
        if index in matched_indices:
            continue
        stale_exceptions.append(exception)
        failures.append(
            "stale or mismatched docs-site advisory exception: "
            f"{exception['advisory']} package={exception['package']} "
            f"node={exception['affected_node']} direct_dependency={exception['direct_dependency']} "
            f"current_version={exception['current_version']}"
        )

    metadata = audit_report.get("metadata")
    vulnerability_counts = {}
    if isinstance(metadata, dict) and isinstance(metadata.get("vulnerabilities"), dict):
        vulnerability_counts = {
            str(key): int(value)
            for key, value in metadata["vulnerabilities"].items()
            if isinstance(value, int)
        }

    return {
        "status": "pass" if not failures else "fail",
        "repo_root": str(repo_root),
        "package_dir": str(package_dir),
        "lockfile": str(lockfile_path),
        "exceptions_path": str(exceptions_path),
        "audit_report_path": str(audit_report_path) if audit_report_path is not None else "",
        "actionable_advisories": actionable_advisories,
        "matched_exceptions": matched_exceptions,
        "unmatched_advisories": unmatched_advisories,
        "stale_exceptions": stale_exceptions,
        "metadata_vulnerabilities": vulnerability_counts,
        "failures": failures,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    package_dir = resolve_path(repo_root, args.package_dir)
    exceptions_path = resolve_path(repo_root, args.exceptions)
    lockfile_path = resolve_path(repo_root, args.lockfile)
    audit_report_path = resolve_path(repo_root, args.audit_report) if args.audit_report else None

    try:
        result = validate_audit(
            repo_root=repo_root,
            package_dir=package_dir,
            exceptions_path=exceptions_path,
            lockfile_path=lockfile_path,
            audit_report_path=audit_report_path,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        result = {
            "status": "fail",
            "failures": [str(exc)],
        }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "pass":
            print("docs-site audit validation passed")
        else:
            print("docs-site audit validation failed", file=sys.stderr)
            for failure in result.get("failures", []):
                print(f"- {failure}", file=sys.stderr)

    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
