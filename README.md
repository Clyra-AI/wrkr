# Wrkr

Wrkr is the deterministic See-layer CLI in the See -> Prove -> Control model.

## Positioning

Wrkr is the AI-DSPM discovery layer in Clyra's governance sequence:

- See: Wrkr discovers AI tools, autonomy context, permissions, and risk.
- Prove: Axym maps Wrkr proof records to compliance controls.
- Control: Gait applies policy enforcement to approved governance decisions.

Wrkr runs standalone and interoperates through shared `Clyra-AI/proof` contracts.

## Status

Wrkr is in v1 contract-hardening phase with deterministic end-to-end workflows implemented for:

- discovery and scan target modes (`init`, `scan`, diff state)
- deterministic detection, policy/profile evaluation, and ranked risk output
- identity lifecycle, manifest generation, and proof chain verification
- compliance evidence export, reporting artifacts, posture scoring, and regression baselines
- deterministic remediation planning (`fix`) and auth-profile safeguards

Coverage and contract health are enforced by:

- acceptance flow tests in `internal/acceptance/v1_acceptance_test.go`
- scenario coverage mapping in `internal/scenarios/coverage_map.json`
- CI contract lanes (`make test-contracts`, `make prepush-full`, CodeQL)

## Quick Start

```bash
# Configure default scan target and split auth profiles.
wrkr init --non-interactive --repo acme/backend --scan-token "$GH_READ_TOKEN" --fix-token "$GH_WRITE_TOKEN" --json

# Scan explicit target modes.
wrkr scan --repo acme/backend --json
wrkr scan --org acme --json
wrkr scan --path ./local-repos --json

# Optional custom policy overlay.
wrkr scan --path ./local-repos --policy ./fixtures/wrkr-policy.yaml --json

# Profile-aware compliance scan and posture score output.
wrkr scan --path ./local-repos --profile standard --json

# Risk report and inventory export views.
wrkr report --top 5 --json
wrkr report --pdf --json
wrkr export --format inventory --json

# Identity lifecycle commands.
wrkr identity list --json
wrkr identity show <agent_id> --json
wrkr identity approve <agent_id> --approver @maria --scope read-only --expires 90d --json
wrkr lifecycle --org acme --json
wrkr manifest generate --json
wrkr score --json
wrkr score --explain
wrkr regress init --baseline ./.wrkr/last-scan.json --json
wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --json
wrkr verify --chain --json
wrkr evidence --frameworks eu-ai-act,soc2 --json
wrkr fix --top 3 --json

# Optional non-deterministic enrichment branch (explicitly opt-in).
wrkr scan --path ./local-repos --enrich --github-api https://api.github.com --json

# Incremental delta scan keyed on (tool_type, location, org).
wrkr scan --org acme --diff --json
```

## Target Contract

Exactly one target source must be selected per scan invocation:

- `--repo <owner/repo>`
- `--org <org>`
- `--path <local-dir>`

Invalid target combinations return exit code `6` with a machine-readable JSON envelope when `--json` is set.

## State and Diff

- Last scan state is persisted locally at `.wrkr/last-scan.json` (override with `--state` or `WRKR_STATE_PATH`).
- Signed proof records are appended to `.wrkr/proof-chain.json` and use local signing material at `.wrkr/proof-signing-key.json`.
- `--diff` reports only added, removed, and permission-changed findings.
- If local state is absent, `--baseline <path>` can provide a CI artifact baseline.

## Detection and Policy

- Structured parsing is used for JSON/YAML/TOML detector surfaces; parse failures are emitted as typed findings.
- Secret detectors only emit credential-presence context and key names, never secret values.
- Policy checks run after detection and emit deterministic `policy_check` and `policy_violation` findings.
- Built-in policy pack is versioned (`core/policy/rules/builtin.yaml`) and loaded on every scan; repo-local `wrkr-policy.yaml` and `--policy` overlays are supported.

## Remediation

- `wrkr fix --top <N> --json` generates deterministic remediation patch previews and commit messages for eligible high-risk findings.
- Unsupported findings are emitted with explicit non-fixable reason codes.
- `wrkr fix --open-pr` requires a write-capable fix profile token (scan-only profile fails closed).

## Evidence Output Safety

`wrkr evidence` is fail-closed on output paths:

- Non-empty, non-managed output directories are blocked.
- Ownership marker `.wrkr-evidence-managed` must be a regular file.
- Marker symlink/directory usage is blocked.
- Unsafe output writes return exit code `8` with `unsafe_operation_blocked`.

## Documentation

- Command reference: `docs/commands/`
- Operator examples/playbooks: `docs/examples/`
- `wrkr-manifest.yaml` open specification: `docs/specs/wrkr-manifest.md`
