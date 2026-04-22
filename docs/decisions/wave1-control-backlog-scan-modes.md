# Wave 1 Control Backlog And Scan Modes

Title: Add governance control backlog, scan quality, and scan modes

Context:
Wrkr already produced raw findings, ranked findings, action paths, inventory, risk, and proof artifacts. Enterprise reviews need a short governance queue that separates Wrkr-native control-path signal from supporting security evidence and avoids generated/package noise becoming the apparent product center.

Decision:
Add a derived `control_backlog` aggregation surface and a separate `scan_quality` appendix. `control_backlog` is built from raw findings, inventory, and action paths; detectors remain raw evidence producers. `scan_quality` owns generated/package suppression context and parser/debug appendix data. Add `wrkr scan --mode quick|governance|deep`, with `governance` as the default and `quick` narrowing the detector set to high-signal governance surfaces.

Alternatives considered:
- Mutating raw findings directly was rejected because existing findings are compatibility evidence and feed diff, risk, proof, and downstream consumers.
- Folding scan quality into the backlog was rejected because generated/package noise should not compete with reviewable control paths.
- Making deep mode the default was rejected because first-value enterprise scans need a govern-first queue rather than exhaustive debug output.

Tradeoffs:
- The backlog is additive and can duplicate some concepts from action paths, but it gives operators a stable decision surface with action, confidence, SLA, and closure fields.
- Generated-path filtering is conservative and can be extended as new package-manager or SDK trees appear.
- Quick mode provides faster signal but may omit lower-priority detector families by design.

Rollback plan:
Because the surfaces are additive, rollback can remove `control_backlog`, `scan_quality`, and `--mode` wiring while leaving raw findings, inventory, risk, proof, and report contracts intact. Existing state readers tolerate missing additive fields.

Validation plan:
- `go test ./core/aggregate/controlbacklog ./core/aggregate/inventory ./core/model -count=1`
- `go test ./core/aggregate/controlbacklog ./core/risk ./core/report -count=1`
- `go test ./core/detect/secrets ./core/detect/workflowcap ./core/aggregate/controlbacklog ./core/risk -count=1`
- `go test ./core/detect/... ./core/source/local ./core/source/github ./core/aggregate/scanquality -count=1`
- `go test ./internal/scenarios -run 'TestControlBacklogGovernance|TestSecretReferenceSemantics' -count=1 -tags=scenario`
- `go test ./internal/e2e/cli_contract -count=1`
- `make test-contracts`
- `make test-perf`
- `make prepush-full`
