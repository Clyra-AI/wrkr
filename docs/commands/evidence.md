# wrkr evidence

## Synopsis

```bash
wrkr evidence --frameworks <comma-separated-frameworks> [--output <dir>] [--state <path>] [--json]
```

## Flags

- `--json`
- `--frameworks`
- `--output`
- `--state`

## Output ownership safety

Evidence output directories are fail-closed:

- Wrkr verifies the saved proof chain before any staged bundle write or publish step.
- Malformed or tampered proof chains fail closed before a new bundle is staged or published.
- Wrkr writes ownership marker `.wrkr-evidence-managed` in managed directories using state-bound marker provenance rather than a static marker body alone.
- A non-empty, non-managed output directory is blocked.
- Marker path must be a regular file with valid marker provenance; symlink, directory, forged legacy-static, or otherwise invalid markers are blocked.
- Wrkr builds bundles in a same-parent staged directory and publishes to `--output` only after manifest generation, signing, and bundle verification succeed.
- If a build fails, Wrkr leaves the prior managed bundle intact or leaves the target path absent; it does not expose a partial new bundle at the final target path.
- Unsafe output directory usage returns exit code `8` with error code `unsafe_operation_blocked`.

## Error classification contract

`wrkr evidence --json` emits stable machine-readable error classes:

- `runtime_failure` (exit `1`) for runtime/environment/state prerequisites (for example missing state snapshot/proof chain/signing material, or malformed/tampered proof chains).
- `invalid_input` (exit `6`) for caller-controlled invalid arguments (for example unknown framework IDs).
- `unsafe_operation_blocked` (exit `8`) for output-path ownership/marker safety violations.

## Coverage semantics

`framework_coverage` is computed from proof/evidence present in the scanned state at run time.

- Coverage percent is an evidence-state signal, not a scanner capability claim.
- Low/0% means controls are currently undocumented or missing in collected evidence.
- Low coverage should trigger remediation work, then another deterministic scan/evidence/report run.
- Generated report artifacts use the same sparse-evidence wording as the human-readable `wrkr report` path: bundled framework mappings remain available even when current findings do not map to bundled controls yet.

Recommended operator actions when coverage is low:

1. Run `wrkr scan --json` against the intended scope and confirm findings were produced.
2. Review prioritized risk/control gaps with `wrkr report --json`.
3. Implement/remediate missing controls and approvals.
4. Re-run `wrkr scan --json`, `wrkr evidence --frameworks ... --json`, and `wrkr report --json` to measure updated evidence state.

## Example

```bash
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./wrkr-evidence --json
```

Security-team handoff example:

```bash
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./wrkr-evidence --json
```

Pair this with the saved-state `wrkr report` and explicit proof-chain verification flow documented in [`docs/examples/security-team.md`](../examples/security-team.md).
`wrkr evidence` now requires the saved proof chain to be intact before it will stage or publish a bundle; it does not replace the explicit operator or CI proof-chain verification gate.

Expected JSON keys: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`, additive `control_evidence`, additive `coverage_note`, `report_artifacts`, additive `source_privacy`, additive `runtime_evidence`, additive `next_steps`.
`coverage_note` is the machine-readable interpretation companion for `framework_coverage`: it states that coverage reflects only controls evidenced in the current scanned state and that low or zero first-run coverage indicates evidence gaps rather than unsupported framework parsing.
`control_evidence` lists each active control backlog item with existing proof events, missing proof requirements, and related proof record ids when present.
`next_steps[]` is additive machine-readable handoff guidance for the bundle that was just produced. It points to the explicit proof-verification step, the audit-facing `wrkr report --json` flow, and the generated evidence/report artifact fields.
Evidence bundle includes deterministic inventory exports at `inventory.json`, `inventory-snapshot.json`, and `inventory.yaml`.
Evidence bundle includes deterministic compliance rollup export at `compliance-summary.json`.
Evidence bundle includes deterministic control proof status at `control-evidence.json`.
Evidence bundle includes deterministic attack-path artifact export at `attack-paths.json` when attack-path scoring is present in scan state.
When `wrkr ingest` has written a managed runtime evidence sidecar next to the selected state file, the evidence bundle includes `runtime-evidence.json` and `runtime-evidence-correlation.json` without mutating scan state.
Evidence bundle metadata includes `source_privacy` in `scan-metadata.json` so auditors can see whether hosted source was retained, whether raw source is included in artifacts, whether serialized locations are logical, and how cleanup finished.
Shareable evidence artifacts do not include raw source contents by default.
Evidence bundle report summaries now carry additive security-visibility context from the scan state, including `unknown_to_security` counts and the reference basis used to derive them.
If the saved scan state does not carry a usable reference basis, Wrkr suppresses `unknown_to_security` wording in downstream summaries rather than inventing that claim.
When the scanned target is `my_setup`, the bundle also includes `personal-inventory-snapshot.json`.
When MCP declarations are present, the bundle also includes `mcp-catalog.json`.

Wrkr evidence packages saved posture into proof artifacts; it does not replace the explicit proof-chain verification gate, package vulnerability scanners, or server-hardening scanners. Gait interoperability remains optional and downstream of this file-based output.

Canonical state and proof-chain path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).
