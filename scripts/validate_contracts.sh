#!/usr/bin/env bash
set -euo pipefail

go test ./testinfra/contracts -run 'TestStory(7(SchemaContractsStable|SkillConflictAndExposureContracts|ConflictDedupeCanonicalContract|ExitCodeContractsAcrossCommandFamilies|EvidenceOutputDirSafetyContracts|EvidenceManifestExcludesOwnershipMarker|CommandAnchorDeterminism)|8(DocsAndCommandAnchorsPresent|ManifestSpecFieldsAndSchemaProfileCoverage))$' -count=1
