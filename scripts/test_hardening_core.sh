#!/usr/bin/env bash
set -euo pipefail

go test ./core/evidence -run 'TestBuildEvidence(RejectsNonManagedNonEmptyOutputDir|RejectsMarkerDirectory|RejectsMarkerSymlink|RejectsSymlinkOutputDir)|TestBuildManifestEntriesRejectsSymlinkFile$' -count=1
go test ./core/source/github -run 'TestAcquireRepoRetriesTransientStatus$' -count=1
go test ./core/verify -run 'TestChain(TamperDetected|MixedSourceCompatibility)$' -count=1
go test ./internal/scenarios -run '^TestScenarioWave42EnterprisePressureHardening$' -tags=scenario -count=1 -timeout="${GO_TEST_TIMEOUT:-20m}"
