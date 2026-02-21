#!/usr/bin/env bash
set -euo pipefail

go test ./core/source/github -run 'Test(ListOrgReposIntegrationSimulatedAPI|AcquireRepoRetriesTransientStatus)$' -count=5
go test ./internal/integration/source -run 'TestIntegrationOrgAcquireWithSimulatedGitHub$' -count=3
