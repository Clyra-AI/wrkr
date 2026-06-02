#!/usr/bin/env bash
set -euo pipefail

go test ./core/source/github -run 'Test(ListOrgReposIntegrationSimulatedAPI|AcquireRepoRetriesTransientStatus)$' -count=5
go test ./internal/integration/source -run 'TestIntegrationOrgAcquireWithSimulatedGitHub$' -count=3
go test ./internal/scenarios -run '^TestScenarioWave42EnterprisePressureChaos$' -tags=scenario -count=1 -timeout="${GO_TEST_TIMEOUT:-20m}"
