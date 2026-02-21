#!/usr/bin/env bash
set -euo pipefail

go test ./testinfra/contracts -run 'TestStory7(SchemaContractsStable|SkillConflictAndExposureContracts|ConflictDedupeCanonicalContract|ExitCodeContractsAcrossCommandFamilies|EvidenceOutputDirSafetyContracts|EvidenceManifestExcludesOwnershipMarker|CommandAnchorDeterminism)$' -count=1
