#!/usr/bin/env bash
set -euo pipefail

scripts/test_hardening_core.sh
scripts/test_hardening_soak.sh
go test ./internal/integration/... -count=1
