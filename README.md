# Wrkr

Wrkr is the deterministic See-layer CLI in the See -> Prove -> Control model.

## Status

Epics 1-4 are implemented.

- Epic 1: source acquisition contracts (`init`, `scan`, source manifests, incremental diff state)
- Epic 2: deterministic detector engine (Claude/Cursor/Codex/Copilot, MCP, skills, CI/headless autonomy, dependencies, secrets, compiled actions) and YAML-backed policy evaluation (`WRKR-001`..`WRKR-015`)
- Epic 3: deterministic inventory aggregation + repo exposure summaries, identity lifecycle manifest/chain updates, ranked risk reporting, posture profiles, and posture score outputs
- Epic 4: signed proof record emission (`scan_finding`, `risk_assessment`, `approval`, lifecycle transitions), proof chain verification, and compliance evidence bundle generation

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
wrkr export --format inventory --json

# Identity lifecycle commands.
wrkr identity list --json
wrkr identity show <agent_id> --json
wrkr identity approve <agent_id> --approver @maria --scope read-only --expires 90d --json
wrkr lifecycle --org acme --json
wrkr score --json
wrkr verify --chain --json
wrkr evidence --frameworks eu-ai-act,soc2 --json

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
