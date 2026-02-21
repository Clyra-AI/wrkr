#!/usr/bin/env bash
set -euo pipefail

go test ./internal/scenarios -run '^TestScenarioContracts$' -count=1
