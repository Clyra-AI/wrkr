#!/usr/bin/env bash
set -euo pipefail

go test ./core/verify -run 'TestChain(TamperDetected|MixedSourceCompatibility)$' -count=5
go test ./internal/e2e/verify -run 'TestE2EVerifyChainSuccessAndTamper$' -count=3
