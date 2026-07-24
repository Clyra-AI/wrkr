#!/usr/bin/env python3
"""Validate and execute the Sprint 0 public-surface freeze-gate receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
# Freeze-gate execution only shells out to fixed local tools after explicit allowlist checks.
import subprocess  # nosec
import sys
import time
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--receipt",
        type=Path,
        default=Path("testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json"),
    )
    parser.add_argument("--output", type=Path, default=Path(".tmp/freeze-gate-runtime-receipt.json"))
    parser.add_argument("--metadata-only", action="store_true")
    parser.add_argument("--print-content-digest", action="store_true")
    parser.add_argument("--require-clean", action="store_true")
    return parser.parse_args()


def git_output(repo_root: Path, *args: str) -> bytes:
    # git is invoked with fixed argv structure and a repo-root cwd derived from the CLI path argument.
    return subprocess.check_output(["git", "-C", str(repo_root), *args])  # nosec


def receipt_content_digest(repo_root: Path, receipt_path: Path, receipt: dict[str, Any]) -> str:
    scopes = receipt.get("validation_scope_paths")
    if not isinstance(scopes, list) or not scopes or not all(isinstance(item, str) and item for item in scopes):
        raise ValueError("receipt validation_scope_paths must be a non-empty string array")
    tracked = git_output(
        repo_root,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        *scopes,
    ).split(b"\0")
    receipt_rel = receipt_path.resolve().relative_to(repo_root.resolve()).as_posix()
    digest = hashlib.sha256()
    included = 0
    for raw_path in sorted(path for path in tracked if path):
        rel = raw_path.decode("utf-8")
        if rel == receipt_rel:
            continue
        path = repo_root / rel
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"receipt validation scope contains a non-regular file: {rel}")
        payload = path.read_bytes()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
        included += 1
    if included == 0:
        raise ValueError("receipt validation scopes matched no tracked files")
    return digest.hexdigest()


def validate_metadata(repo_root: Path, receipt_path: Path, receipt: dict[str, Any]) -> str:
    if receipt.get("validation_contract_version") != 2:
        raise ValueError("receipt validation_contract_version must be 2")
    if receipt.get("status") != "green":
        raise ValueError("receipt status must be green")
    actual_digest = receipt_content_digest(repo_root, receipt_path, receipt)
    if receipt.get("validated_content_sha256") != actual_digest:
        raise ValueError(
            "receipt content digest is stale: "
            f"recorded={receipt.get('validated_content_sha256')} actual={actual_digest}"
        )

    rows = receipt.get("artifact_size_deltas")
    if not isinstance(rows, list) or not rows:
        raise ValueError("receipt artifact_size_deltas must be non-empty")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"artifact_size_deltas[{index}] must be an object")
        raw_measured = row.get("measured_bytes")
        raw_baseline = row.get("baseline_bytes")
        raw_budget = row.get("budget_bytes")
        raw_delta = row.get("delta_bytes")
        if (
            not isinstance(raw_measured, int)
            or not isinstance(raw_baseline, int)
            or not isinstance(raw_budget, int)
            or not isinstance(raw_delta, int)
        ):
            raise ValueError(f"artifact_size_deltas[{index}] requires integer byte fields")
        measured = raw_measured
        baseline = raw_baseline
        budget = raw_budget
        delta = raw_delta
        if measured <= 0 or baseline < 0 or budget <= 0:
            raise ValueError(f"artifact_size_deltas[{index}] contains non-positive measurements")
        if measured > budget:
            raise ValueError(f"artifact_size_deltas[{index}] exceeds its committed budget")
        if measured - baseline != delta:
            raise ValueError(f"artifact_size_deltas[{index}] delta does not match measured-baseline")
        if not str(row.get("measurement_source", "")).strip():
            raise ValueError(f"artifact_size_deltas[{index}] missing measurement_source")

    validations = receipt.get("validations")
    if not isinstance(validations, list) or not validations:
        raise ValueError("receipt validations must be non-empty")
    for index, validation in enumerate(validations):
        if not isinstance(validation, dict) or validation.get("status") != "pass":
            raise ValueError(f"validations[{index}] must be a passing object")
        commands = validation.get("commands")
        fixtures = validation.get("fixture_names")
        if not isinstance(commands, list) or not commands:
            raise ValueError(f"validations[{index}] commands must be non-empty")
        if not isinstance(fixtures, list) or not fixtures:
            raise ValueError(f"validations[{index}] fixture_names must be non-empty")
    return actual_digest


def unique_commands(receipt: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    seen: set[str] = set()
    for validation in receipt["validations"]:
        for raw in validation["commands"]:
            command = str(raw).strip()
            if command and command not in seen:
                seen.add(command)
                commands.append(command)
    return commands


def execute_command(repo_root: Path, command: str) -> dict[str, Any]:
    argv = shlex.split(command)
    direct_go_test = len(argv) >= 2 and argv[0] == "go" and argv[1] == "test"
    exact_fixture_check = argv == ["scripts/generate_action_contract_conformance.sh", "--check"]
    if not direct_go_test and not exact_fixture_check:
        raise ValueError(f"freeze-gate command is not allowlisted for direct execution: {command}")
    started = time.monotonic()
    # argv is limited to direct `go test` or one fixed fixture script above; shell is never enabled.
    completed = subprocess.run(  # nosec
        argv,
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = completed.stdout
    return {
        "command": command,
        "exit_code": completed.returncode,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output_bytes": len(output),
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


def write_runtime_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    receipt_path = args.receipt if args.receipt.is_absolute() else repo_root / args.receipt
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if args.print_content_digest:
            print(receipt_content_digest(repo_root, receipt_path, receipt))
            return 0
        content_digest = validate_metadata(repo_root, receipt_path, receipt)
        dirty = bool(git_output(repo_root, "status", "--porcelain").strip())
        if args.require_clean and dirty:
            raise ValueError("freeze-gate execution requires a clean worktree")
        if args.metadata_only:
            print(f"freeze gate metadata: pass content_sha256={content_digest}")
            return 0

        results: list[dict[str, Any]] = []
        status = "pass"
        for command in unique_commands(receipt):
            result = execute_command(repo_root, command)
            results.append(result)
            if result["exit_code"] != 0:
                status = "fail"
                break
        runtime = {
            "artifact_type": "freeze_gate_runtime_receipt",
            "version": 1,
            "status": status,
            "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "commit_sha": git_output(repo_root, "rev-parse", "HEAD").decode("utf-8").strip(),
            "worktree_dirty": dirty,
            "validated_content_sha256": content_digest,
            "source_receipt": receipt_path.resolve().relative_to(repo_root).as_posix(),
            "source_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "command_results": results,
        }
        output_path = args.output if args.output.is_absolute() else repo_root / args.output
        write_runtime_receipt(output_path, runtime)
        if status != "pass":
            raise ValueError(f"freeze-gate command failed: {results[-1]['command']}")
        print(
            f"freeze gate execution: pass commands={len(results)} "
            f"content_sha256={content_digest} runtime_receipt={output_path}"
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"freeze gate: fail: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
