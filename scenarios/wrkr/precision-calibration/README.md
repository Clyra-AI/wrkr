# Precision Calibration Fixture

This scenario is a compact, fake-data calibration pack for repeated buyer pain
points that should never depend on customer scans.

Each repo calibrates one known-outcome case:

- `owner-evidence`: explicit CODEOWNERS-backed ownership evidence.
- `approval-sidecar`: approval evidence carried by a repo-local
  external-control sidecar.
- `non-prod-contradiction`: declared non-production target contradicted by a
  production secret-bearing workflow.
- `dependency-only`: AI dependencies present without an executable agent path.
- `ci-without-agent`: CI automation that must stay CI-shaped instead of being
  mislabeled as an agent.
- `deploy-agent`: AI-assisted deploy workflow with runtime evidence correlation.
- `branch-protected`: branch-protection evidence present.
- `branch-unprotected`: same workflow shape without branch-protection evidence.
- `source-only-old`: source-only agent code that should stay context-first.

`internal/scenarios/wave41_precision_calibration_scenario_test.go` projects the
stable expected outcome surface into `expected/calibration-summary.json`.
