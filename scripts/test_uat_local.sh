#!/usr/bin/env bash
set -euo pipefail

skip_global_gates="false"
release_version="${WRKR_UAT_RELEASE_VERSION:-}"
brew_formula="${WRKR_UAT_BREW_FORMULA:-}"
go_install_module="github.com/Clyra-AI/wrkr/cmd/wrkr"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-global-gates)
      skip_global_gates="true"
      shift
      ;;
    --release-version)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --release-version" >&2
        exit 6
      fi
      release_version="$2"
      shift 2
      ;;
    --brew-formula)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --brew-formula" >&2
        exit 6
      fi
      brew_formula="$2"
      shift 2
      ;;
    *)
      echo "unsupported argument: $1" >&2
      exit 6
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

mkdir -p .tmp
tmp_dir="$(mktemp -d .tmp/uat-local.XXXXXX)"
tmp_dir="$(cd "$tmp_dir" && pwd)"

cleanup() {
  if [[ -n "${brew_local_tap_name:-}" ]]; then
    brew untap "$brew_local_tap_name" >/dev/null 2>&1 || true
  fi
  if [[ -n "${brew_local_formula_name:-}" ]]; then
    brew uninstall --formula "$brew_local_formula_name" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

root_json_smoke_validator="$tmp_dir/check_root_json_smoke.go"
cat >"$root_json_smoke_validator" <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type rootPayload struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go run <validator> <path> <label>")
		os.Exit(6)
	}

	path := strings.TrimSpace(os.Args[1])
	payload, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "json smoke read failure")
		os.Exit(3)
	}

	var parsed rootPayload
	if err := json.Unmarshal(payload, &parsed); err != nil {
		fmt.Fprintln(os.Stderr, "json smoke parse failure")
		os.Exit(3)
	}

	if strings.TrimSpace(parsed.Status) != "ok" {
		fmt.Fprintln(os.Stderr, "json smoke status mismatch")
		os.Exit(3)
	}
	if strings.TrimSpace(parsed.Message) == "" {
		fmt.Fprintln(os.Stderr, "json smoke missing message")
		os.Exit(3)
	}
}
GO

version_json_smoke_validator="$tmp_dir/check_version_json_smoke.go"
cat >"$version_json_smoke_validator" <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type versionPayload struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintln(os.Stderr, "usage: go run <validator> <path> <label> [expected-version]")
		os.Exit(6)
	}

	path := strings.TrimSpace(os.Args[1])
	expectedVersion := ""
	if len(os.Args) == 4 {
		expectedVersion = strings.TrimSpace(os.Args[3])
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "version smoke read failure")
		os.Exit(3)
	}

	var parsed versionPayload
	if err := json.Unmarshal(payload, &parsed); err != nil {
		fmt.Fprintln(os.Stderr, "version smoke parse failure")
		os.Exit(3)
	}

	if strings.TrimSpace(parsed.Status) != "ok" {
		fmt.Fprintln(os.Stderr, "version smoke status mismatch")
		os.Exit(3)
	}
	if strings.TrimSpace(parsed.Version) == "" {
		fmt.Fprintln(os.Stderr, "version smoke missing version")
		os.Exit(3)
	}
	if expectedVersion != "" && strings.TrimSpace(parsed.Version) != expectedVersion {
		fmt.Fprintln(os.Stderr, "version smoke version mismatch")
		os.Exit(3)
	}
}
GO

run_root_json_smoke() {
  local label="$1"
  local bin_path="$2"
  local out_path="$tmp_dir/${label}.json"

  if [[ ! -x "$bin_path" ]]; then
    echo "binary is not executable for ${label}: $bin_path" >&2
    exit 7
  fi

  "$bin_path" --json >"$out_path"
  go run "$root_json_smoke_validator" "$out_path" "$label"
}

run_version_json_smoke() {
  local label="$1"
  local bin_path="$2"
  local expected_version="${3:-}"
  local out_path="$tmp_dir/${label}-version.json"

  if [[ ! -x "$bin_path" ]]; then
    echo "binary is not executable for ${label}: $bin_path" >&2
    exit 7
  fi

  "$bin_path" version --json >"$out_path"
  go run "$version_json_smoke_validator" "$out_path" "$label" "$expected_version"
}

run_json_smoke() {
  local label="$1"
  local bin_path="$2"
  local expected_version="${3:-}"

  run_root_json_smoke "$label" "$bin_path"
  run_version_json_smoke "$label" "$bin_path" "$expected_version"
}

run_install_smoke() {
  local label="$1"
  local bin_path="$2"
  local expected_version="${3:-}"

  run_json_smoke "$label" "$bin_path" "$expected_version"
  run_docs_subset_smoke "$label" "$bin_path"
}

run_docs_subset_smoke() {
  local label="$1"
  local bin_path="$2"

  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found; skipping docs subset smoke for ${label}" >"$tmp_dir/${label}-docs-smoke.log"
    return
  fi

  WRKR_BIN="$bin_path" scripts/run_docs_smoke.sh --subset >"$tmp_dir/${label}-docs-smoke.log"
}

run_go_install_smoke() {
  local label="$1"
  local install_target="$2"
  local expected_version="${3:-}"
  local install_bin_dir="$tmp_dir/${label}-gobin"
  local install_bin="$install_bin_dir/wrkr"

  rm -rf "$install_bin_dir"
  mkdir -p "$install_bin_dir"
  GOBIN="$install_bin_dir" go install "$install_target"

  if [[ ! -x "$install_bin" ]]; then
    echo "go install did not produce wrkr binary for ${label}: ${install_target}" >&2
    exit 7
  fi

  run_install_smoke "$label" "$install_bin" "$expected_version"
}

if [[ "$skip_global_gates" != "true" ]]; then
  make lint-fast
  go test $(scripts/first_party_go_packages.sh) -count=1
  make test-contracts
  scripts/validate_contracts.sh
  scripts/validate_scenarios.sh
  go test ./internal/scenarios -count=1 -tags=scenario
  go test ./internal/integration/interop -count=1
  scripts/test_hardening_core.sh
  scripts/test_perf_budgets.sh
fi

source_bin="$tmp_dir/wrkr-source"
go build -o "$source_bin" ./cmd/wrkr
run_install_smoke "source" "$source_bin"
run_go_install_smoke "go-install-local" "./cmd/wrkr"

os_name="$(uname -s)"
case "$os_name" in
  Darwin)
    goos="darwin"
    ;;
  Linux)
    goos="linux"
    ;;
  *)
    echo "unsupported OS for UAT install-path checks: $os_name" >&2
    exit 6
    ;;
esac

arch_name="$(uname -m)"
case "$arch_name" in
  arm64|aarch64)
    goarch="arm64"
    ;;
  x86_64|amd64)
    goarch="amd64"
    ;;
  *)
    echo "unsupported CPU architecture for UAT install-path checks: $arch_name" >&2
    exit 6
    ;;
esac

release_archive="$tmp_dir/wrkr-release.tar.gz"

if [[ -n "$release_version" ]]; then
  release_tag="$release_version"
  if [[ "$release_tag" != v* ]]; then
    release_tag="v${release_tag}"
  fi
  release_version_no_v="${release_tag#v}"
  archive_name="wrkr_${release_version_no_v}_${goos}_${goarch}.tar.gz"
  archive_url="https://github.com/Clyra-AI/wrkr/releases/download/${release_tag}/${archive_name}"
  curl -fsSL "$archive_url" -o "$release_archive"
else
  archive_stage="$tmp_dir/archive-stage"
  mkdir -p "$archive_stage"
  cp "$source_bin" "$archive_stage/wrkr"
  tar -C "$archive_stage" -czf "$release_archive" wrkr
fi

if [[ -n "${release_tag:-}" ]]; then
  # This mirrors the README/docs install command pinned to a concrete release tag.
  run_go_install_smoke "go-install-release-tag" "${go_install_module}@${release_tag}" "${release_tag}"
fi

release_extract_dir="$tmp_dir/release-extract"
mkdir -p "$release_extract_dir"
tar -xzf "$release_archive" -C "$release_extract_dir"

release_bin=""
while IFS= read -r candidate; do
  if [[ -x "$candidate" ]]; then
    release_bin="$candidate"
    break
  fi
done < <(find "$release_extract_dir" -type f -name wrkr)

if [[ -z "$release_bin" ]]; then
  echo "could not find extracted wrkr binary in release archive" >&2
  exit 7
fi

run_install_smoke "release-installer" "$release_bin" "${release_tag:-}"

if ! command -v brew >/dev/null 2>&1; then
  echo "homebrew is required for UAT homebrew-path checks" >&2
  exit 7
fi

export HOMEBREW_NO_AUTO_UPDATE=1

if [[ -n "$brew_formula" ]]; then
  brew install "$brew_formula"
  brew_bin="$(command -v wrkr || true)"
  if [[ -z "$brew_bin" ]]; then
    echo "brew formula installed but wrkr was not found on PATH" >&2
    exit 7
  fi
  run_json_smoke "homebrew" "$brew_bin"
  run_docs_subset_smoke "homebrew" "$brew_bin"
else
  brew_local_formula_name="wrkr-uat-local"
  brew_local_tap_name="wrkr/uat-local"
  release_archive_sha="$(shasum -a 256 "$release_archive" | awk '{print $1}')"
  brew_local_tap_dir="$(brew --repository)/Library/Taps/wrkr/homebrew-uat-local"
  brew_local_formula_path="$brew_local_tap_dir/Formula/${brew_local_formula_name}.rb"

  brew untap "$brew_local_tap_name" >/dev/null 2>&1 || true
  brew tap-new --no-git "$brew_local_tap_name"

  mkdir -p "$(dirname "$brew_local_formula_path")"
  cat >"$brew_local_formula_path" <<RB
class WrkrUatLocal < Formula
  desc "Wrkr local UAT formula"
  homepage "https://github.com/Clyra-AI/wrkr"
  url "file://${release_archive}"
  sha256 "${release_archive_sha}"
  version "0.0.0-uat"

  def install
    bin.install "wrkr" => "wrkr-uat-local"
  end

  test do
    output = shell_output("#{bin}/wrkr-uat-local --json")
    assert_match "\"status\":\"ok\"", output
  end
end
RB

  brew install "$brew_local_tap_name/$brew_local_formula_name"
  brew_bin="$(brew --prefix)/bin/wrkr-uat-local"
  run_json_smoke "homebrew-local-formula" "$brew_bin"
  run_docs_subset_smoke "homebrew-local-formula" "$brew_bin"
  brew test "$brew_local_tap_name/$brew_local_formula_name"
fi

echo "uat local install-path checks: pass"
