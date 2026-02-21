#!/usr/bin/env bash
set -euo pipefail

go test ./core/evidence -run 'TestBuildEvidence(RejectsNonManagedNonEmptyOutputDir|RejectsMarkerDirectory|RejectsMarkerSymlink|RejectsSymlinkOutputDir|BuildManifestEntriesRejectsSymlinkFile)$' -count=1
go test ./core/source/github -run 'TestAcquireRepoRetriesTransientStatus$' -count=1
go test ./core/verify -run 'TestChain(TamperDetected|MixedSourceCompatibility)$' -count=1
