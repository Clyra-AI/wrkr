#!/usr/bin/env bash
set -euo pipefail

dev_guides_path="${WRKR_PIN_CHECK_DEV_GUIDES:-product/dev_guides.md}"
targets_raw="${WRKR_PIN_CHECK_TARGETS:-.github/workflows/*.yml Makefile}"
pin_target_files=()

contains_value() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

resolve_pin_target_files() {
  local -a patterns=()
  read -r -a patterns <<<"$targets_raw"

  shopt -s nullglob
  local pattern
  local file
  for pattern in "${patterns[@]}"; do
    if [[ "$pattern" == *"*"* || "$pattern" == *"?"* || "$pattern" == *"["* ]]; then
      for file in $pattern; do
        if [[ -f "$file" ]]; then
          pin_target_files+=("$file")
        fi
      done
      continue
    fi
    if [[ -f "$pattern" ]]; then
      pin_target_files+=("$pattern")
    fi
  done
  shopt -u nullglob

  if [[ ${#pin_target_files[@]} -eq 0 ]]; then
    echo "missing pin enforcement targets: $targets_raw" >&2
    exit 3
  fi
}

read_expected_pin() {
  local tool="$1"
  awk -F'|' -v tool="$tool" '
    $0 ~ "^\\|[[:space:]]*" tool "[[:space:]]*\\|" {
      version = $3
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", version)
      gsub(/`/, "", version)
      if (version != "") {
        print version
        found = 1
        exit 0
      }
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' "$dev_guides_path"
}

extract_versions_from_file() {
  local module="$1"
  local file="$2"
  awk -v module="$module@" '
    {
      line = $0
      while (1) {
        idx = index(line, module)
        if (idx == 0) {
          break
        }
        rest = substr(line, idx + length(module))
        if (match(rest, /^v[^"[:space:]]+/)) {
          print substr(rest, RSTART, RLENGTH)
          line = substr(rest, RSTART + RLENGTH)
        } else {
          break
        }
      }
    }
  ' "$file"
}

check_enforced_pin() {
  local tool="$1"
  local module="$2"
  local expected_version="$3"
  local -a observed_versions=()
  local -a observed_sources=()
  local file
  local version

  for file in "${pin_target_files[@]}"; do
    while IFS= read -r version; do
      if [[ -z "$version" ]]; then
        continue
      fi
      observed_versions+=("$version")
      observed_sources+=("$file")
    done < <(extract_versions_from_file "$module" "$file")
  done

  if [[ ${#observed_versions[@]} -eq 0 ]]; then
    echo "missing enforced pin for $tool in targets: ${pin_target_files[*]}" >&2
    exit 3
  fi

  local -a unique_versions=()
  for version in "${observed_versions[@]}"; do
    if [[ ${#unique_versions[@]} -eq 0 ]] || ! contains_value "$version" "${unique_versions[@]}"; then
      unique_versions+=("$version")
    fi
  done

  if [[ ${#unique_versions[@]} -ne 1 ]]; then
    echo "pin mismatch for $tool: expected $expected_version from $dev_guides_path, found multiple versions ${unique_versions[*]} in targets: ${pin_target_files[*]}" >&2
    exit 3
  fi

  if [[ "${unique_versions[0]}" != "$expected_version" ]]; then
    local actual_version="${unique_versions[0]}"
    local source_path="${pin_target_files[0]}"
    local idx
    for idx in "${!observed_versions[@]}"; do
      if [[ "${observed_versions[$idx]}" == "$actual_version" ]]; then
        source_path="${observed_sources[$idx]}"
        break
      fi
    done
    echo "pin mismatch for $tool: expected $expected_version from $dev_guides_path, found $actual_version in $source_path" >&2
    exit 3
  fi
}

if [[ ! -f .tool-versions ]]; then
  echo "missing .tool-versions" >&2
  exit 3
fi

if [[ ! -f "$dev_guides_path" ]]; then
  echo "missing standards file: $dev_guides_path" >&2
  exit 3
fi

resolve_pin_target_files

expected=(
  "golang 1.25.7"
  "python 3.13.1"
  "nodejs 22.14.0"
)
for line in "${expected[@]}"; do
  if ! grep -Fxq "$line" .tool-versions; then
    echo "missing pinned toolchain line: $line" >&2
    exit 3
  fi
done

if grep -Eq '^go 1\.25\.7$' go.mod; then
  :
elif grep -Eq '^toolchain go1\.25\.7$' go.mod; then
  :
else
  echo "go.mod must pin go toolchain version 1.25.7 (toolchain or go directive)" >&2
  exit 3
fi

gosec_expected="$(read_expected_pin "gosec" || true)"
if [[ -z "$gosec_expected" ]]; then
  echo "missing expected pin in $dev_guides_path for gosec" >&2
  exit 3
fi

golangci_lint_expected="$(read_expected_pin "golangci-lint" || true)"
if [[ -z "$golangci_lint_expected" ]]; then
  echo "missing expected pin in $dev_guides_path for golangci-lint" >&2
  exit 3
fi

check_enforced_pin "gosec" "github.com/securego/gosec/v2/cmd/gosec" "$gosec_expected"
check_enforced_pin "golangci-lint" "github.com/golangci/golangci-lint/cmd/golangci-lint" "$golangci_lint_expected"
