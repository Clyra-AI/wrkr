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
- Wrkr writes ownership marker `.wrkr-evidence-managed` in managed directories.
- A non-empty, non-managed output directory is blocked.
- Marker path must be a regular file; symlink or directory markers are blocked.
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

Expected JSON keys: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`, `report_artifacts`.
Evidence bundle includes deterministic inventory exports at `inventory.json`, `inventory-snapshot.json`, and `inventory.yaml`.
Evidence bundle includes deterministic compliance rollup export at `compliance-summary.json`.
Evidence bundle includes deterministic attack-path artifact export at `attack-paths.json` when attack-path scoring is present in scan state.
Evidence bundle report summaries now carry additive security-visibility context from the scan state, including `unknown_to_security` counts and the reference basis used to derive them.
If the saved scan state does not carry a usable reference basis, Wrkr suppresses `unknown_to_security` wording in downstream summaries rather than inventing that claim.
When the scanned target is `my_setup`, the bundle also includes `personal-inventory-snapshot.json`.
When MCP declarations are present, the bundle also includes `mcp-catalog.json`.

Wrkr evidence packages saved posture into proof artifacts; it does not replace the explicit proof-chain verification gate, package vulnerability scanners, or server-hardening scanners. Gait interoperability remains optional and downstream of this file-based output.

Canonical state and proof-chain path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).
