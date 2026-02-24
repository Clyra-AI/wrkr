#!/usr/bin/env bash
set -euo pipefail

go test ./core/detect/mcp/enrich -count=1
go test ./core/detect/mcp -run 'TestDetectMCPEnrichAddsNormalizedEvidence|TestDetectMCPServersAndTrustSignals|TestDetectMCPServerOrderIsDeterministic' -count=1

