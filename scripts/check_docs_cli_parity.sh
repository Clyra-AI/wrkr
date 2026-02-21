#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for docs parity checks" >&2
  exit 7
fi

python3 - <<'PY'
import pathlib
import re
import sys

repo = pathlib.Path(".")

required_docs = {
    "docs/commands/index.md",
    "docs/commands/root.md",
    "docs/commands/init.md",
    "docs/commands/scan.md",
    "docs/commands/report.md",
    "docs/commands/export.md",
    "docs/commands/identity.md",
    "docs/commands/lifecycle.md",
    "docs/commands/manifest.md",
    "docs/commands/regress.md",
    "docs/commands/score.md",
    "docs/commands/verify.md",
    "docs/commands/evidence.md",
    "docs/commands/fix.md",
    "docs/examples/quickstart.md",
    "docs/examples/operator-playbooks.md",
}

missing = [path for path in sorted(required_docs) if not (repo / path).is_file()]
if missing:
    for path in missing:
        print(f"missing docs file: {path}", file=sys.stderr)
    sys.exit(3)

root_source = (repo / "core/cli/root.go").read_text(encoding="utf-8")
root_commands = sorted(set(re.findall(r'case\s+"([a-z]+)"\s*:', root_source)))
index_text = (repo / "docs/commands/index.md").read_text(encoding="utf-8")
for command in root_commands:
    token = f"wrkr {command}"
    if token not in index_text:
        print(f"docs/commands/index.md missing command entry: {token}", file=sys.stderr)
        sys.exit(3)

exit_codes = re.findall(r"exit[A-Za-z]+\s*=\s*(\d+)", root_source)
root_doc = (repo / "docs/commands/root.md").read_text(encoding="utf-8")
for code in sorted(set(exit_codes), key=int):
    if f"`{code}`" not in root_doc:
        print(f"docs/commands/root.md missing exit code `{code}`", file=sys.stderr)
        sys.exit(3)

flag_pattern = re.compile(r'fs\.(?:Bool|String|Int|Duration)\("([a-z0-9-]+)"')

source_to_doc = {
    "core/cli/root.go": "docs/commands/root.md",
    "core/cli/init.go": "docs/commands/init.md",
    "core/cli/scan.go": "docs/commands/scan.md",
    "core/cli/report.go": "docs/commands/report.md",
    "core/cli/export.go": "docs/commands/export.md",
    "core/cli/identity.go": "docs/commands/identity.md",
    "core/cli/lifecycle.go": "docs/commands/lifecycle.md",
    "core/cli/manifest.go": "docs/commands/manifest.md",
    "core/cli/regress.go": "docs/commands/regress.md",
    "core/cli/score.go": "docs/commands/score.md",
    "core/cli/verify.go": "docs/commands/verify.md",
    "core/cli/evidence.go": "docs/commands/evidence.md",
    "core/cli/fix.go": "docs/commands/fix.md",
}

def extract_flags(path: pathlib.Path) -> set[str]:
    return set(flag_pattern.findall(path.read_text(encoding="utf-8")))

for source_path, doc_path in source_to_doc.items():
    source_flags = extract_flags(repo / source_path)
    doc_text = (repo / doc_path).read_text(encoding="utf-8")
    doc_flags = set(re.findall(r"--[a-z0-9-]+", doc_text))

    missing_flags = sorted(f"--{flag}" for flag in source_flags if f"--{flag}" not in doc_text)
    if missing_flags:
        print(f"{doc_path} missing flags from {source_path}: {', '.join(missing_flags)}", file=sys.stderr)
        sys.exit(3)

    allowed_doc_flags = set(f"--{flag}" for flag in source_flags)
    stale_flags = sorted(flag for flag in doc_flags if flag not in allowed_doc_flags)
    if stale_flags:
        print(f"{doc_path} contains undocumented/stale flags not in {source_path}: {', '.join(stale_flags)}", file=sys.stderr)
        sys.exit(3)

print("docs CLI parity: pass")
PY
