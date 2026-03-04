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

run_json_smoke() {
  local label="$1"
  local bin_path="$2"
  local out_path="$tmp_dir/${label}.json"

  if [[ ! -x "$bin_path" ]]; then
    echo "binary is not executable for ${label}: $bin_path" >&2
    exit 7
  fi

  "$bin_path" --json >"$out_path"
  go run ./scripts/check_json_smoke.go "$out_path" "$label"
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
  local install_bin_dir="$tmp_dir/${label}-gobin"
  local install_bin="$install_bin_dir/wrkr"

  rm -rf "$install_bin_dir"
  mkdir -p "$install_bin_dir"
  GOBIN="$install_bin_dir" go install "$install_target"

  if [[ ! -x "$install_bin" ]]; then
    echo "go install did not produce wrkr binary for ${label}: ${install_target}" >&2
    exit 7
  fi

  run_json_smoke "$label" "$install_bin"
  run_docs_subset_smoke "$label" "$install_bin"
}

if [[ "$skip_global_gates" != "true" ]]; then
  make lint-fast
  go test ./... -count=1
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
run_json_smoke "source" "$source_bin"
run_docs_subset_smoke "source" "$source_bin"
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
  run_go_install_smoke "go-install-release-tag" "${go_install_module}@${release_tag}"
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

run_json_smoke "release-installer" "$release_bin"
run_docs_subset_smoke "release-installer" "$release_bin"

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
  brew tap-new "$brew_local_tap_name"

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
