#!/usr/bin/env bash
set -euo pipefail

scripts/test_chaos_proof.sh
scripts/test_chaos_source.sh
go test ./core/risk -run 'TestBuildComposedActionPathsMultiStage(MissingMiddleEvidenceAndCyclesFailClosed|RejectsUnknownTrustBoundaryAndWeakRefs|RejectsMalformedCorrelationRefs|RepeatedTrustBoundariesStayDeduplicated|DepthAndCandidateCapsAreExplicit)$' -count=1
