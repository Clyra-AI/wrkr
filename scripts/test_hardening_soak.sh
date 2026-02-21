#!/usr/bin/env bash
set -euo pipefail

export LOCK_PROFILE="${LOCK_PROFILE:-swarm}"
export LOCK_TIMEOUT="${LOCK_TIMEOUT:-5s}"
export LOCK_RETRY="${LOCK_RETRY:-10ms}"

go test ./internal/e2e/diff -run 'TestE2EDiffNoNoiseOnUnchangedInput$' -count=4
go test ./internal/e2e/regress -run 'TestE2ERegressInitAndRunDetectsDrift$' -count=4
