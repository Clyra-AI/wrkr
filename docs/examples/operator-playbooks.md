# Operator Playbooks

Canonical local artifact locations are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

## Scan workflow

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile assessment --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
wrkr scan status --state ./.wrkr/last-scan.json --json
wrkr export tickets --top 10 --format jira --dry-run --state ./.wrkr/last-scan.json --json
```

Check `top_findings`, additive `action_paths`, additive `action_path_to_control_first`, `attack_paths`, `top_attack_paths`, `repo_exposure_summaries`, `profile`, and optional `report.md_path`.
For prompt-channel and enrich-enabled MCP findings, confirm stable evidence metadata fields are present (`pattern_family`, `evidence_snippet_hash`, `enrich_quality`, `as_of`, `source`).

### Ownership-quality review

For org-scale governance, review owner quality from `control_backlog.items[*]`, `inventory.tools[*].locations[*]`, and `agent_privilege_map[*]`.
The compatibility fields `owner_source` and `ownership_status` remain present, while the additive `ownership_state`, `ownership_confidence`, `ownership_evidence_basis`, and `ownership_conflicts` fields distinguish explicit owners, inferred owners, conflicting owners, and missing owners.

Wrkr resolves local ownership from CODEOWNERS, optional `.wrkr/owners.*` mappings, service catalog exports, and Backstage `catalog-info.yaml` files. GitHub topics or teams are used only when they are already present in acquired source metadata; Wrkr does not perform standalone ownership lookups by default.

### Large-org background pattern

```bash
nohup wrkr scan --github-org acme --github-api https://api.github.com --state ./.wrkr/last-scan.json --json --json-path ./.wrkr/scan.json > ./.wrkr/scan.stdout 2> ./.wrkr/scan.stderr &
wrkr scan status --state ./.wrkr/last-scan.json --json
```

Wrkr does not start a hidden scan daemon. The status sidecar records `running`, `completed`, `interrupted`, or `failed` state, current phase, last successful phase, repo counts, partial marker, phase timings, and artifact paths.

### Ticket export dry run

Use ticket export after a scan has produced a saved control backlog:

```bash
wrkr export tickets --top 10 --format jira --dry-run --state ./.wrkr/last-scan.json --json
wrkr export tickets --top 10 --format github --dry-run --state ./.wrkr/last-scan.json --json
wrkr export tickets --top 10 --format servicenow --dry-run --state ./.wrkr/last-scan.json --json
```

Dry-run ticket export is local JSON payload generation only. It groups deterministically by owner, repo, and control path and includes owner, evidence, recommended action, SLA, closure criteria, confidence, and proof requirements.

## Shareable report workflow

```bash
wrkr report --md --md-path ./.tmp/wrkr-summary.md --template operator --share-profile internal --json
wrkr report --template agent-action-bom --json --evidence-json --evidence-json-path ./.tmp/agent-action-bom-evidence.json
wrkr report --md --md-path ./.tmp/wrkr-summary-public.md --template public --share-profile public --json
wrkr report --pdf --pdf-path ./.tmp/wrkr-summary.pdf --template exec --json
```

Use internal profile for engineering/security reviews. Use public profile for external packets with deterministic redaction. The exec PDF path now wraps and paginates long content so the executive summary stays board-ready when the acceptance fixtures are green.
Use `report --template agent-action-bom` when you want the canonical joined action-path inventory with proof refs, graph refs, runtime evidence correlation, credential classification, and next-action priority without manually joining `action_paths`, `control_path_graph`, and evidence fields.
Use `./scripts/run_agent_action_bom_demo.sh after` when you need a deterministic before/after fixture that proves the static discovery -> runtime evidence -> evidence bundle story end to end.
The report path is static and saved-state based: it summarizes risky write paths, proof artifacts, and governance priorities without claiming runtime observation or control-layer enforcement.
`report --json` now includes additive `next_steps[]` guidance that points operators toward the current report artifact fields, the follow-on evidence bundle flow, and explicit proof-chain verification before external handoff.

### Buyer/GRC-ready packet

Use this packet when the operator needs to hand the result to a buyer, GRC partner, or auditor:

- `wrkr report --template ciso --md --md-path ./.tmp/ciso.md --pdf --pdf-path ./.tmp/ciso.pdf --evidence-json --evidence-json-path ./.tmp/report-evidence.json --csv-backlog --csv-backlog-path ./.tmp/control-backlog.csv --json`
- `wrkr report --template agent-action-bom --json --evidence-json --evidence-json-path ./.tmp/agent-action-bom-evidence.json`
- `wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --output ./.tmp/evidence --json`
- `wrkr verify --chain --json`

Operator curates and explains the packet. Buyer/GRC consumer reads the generated Markdown/PDF plus the evidence bundle and proof verification result; they do not need to rerun the scan to review the output.

## Fix workflow

```bash
wrkr fix --top 3 --json
wrkr fix --top 3 --apply --open-pr --max-prs 2 --repo acme/backend --json
```

Check `remediation_count`, deterministic `fingerprint`, `apply_supported`, and unsupported finding reasons. Use preview mode for broad deterministic guidance and `--apply` only when you want supported repo-file changes published via PRs.

## Evidence workflow

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
```

Check `framework_coverage`, additive `coverage_note`, `report_artifacts`, and manifest/chain paths.
When risk state includes attack-path scoring, evidence output includes deterministic `attack-paths.json`.
`evidence --json` now includes additive `next_steps[]` guidance that points operators toward explicit proof verification, audit-facing report rendering, and the generated bundle/report artifact fields.

`framework_coverage` reflects evidence currently present in scanned state.
`coverage_note` is the additive machine-readable interpretation of that value and should be preferred when you need to explain low/zero first-run coverage to operators or downstream automation.

- Low/0% coverage indicates documented control gaps in current evidence.
- Low/0% does not imply Wrkr lacks support for that framework.
- Treat low coverage as an action queue: remediate, rescan, and regenerate report/evidence artifacts.
- When current findings do not yet map to bundled controls, the generated report summary explicitly says framework mappings are still available and that the current state is evidence-sparse.

Recommended low-coverage response:

1. Run `wrkr report --top 5 --json` to prioritize the highest-risk missing controls.
2. Complete control implementation or lifecycle approvals for the affected identities/tools.
3. Re-run `wrkr scan --json`, then `wrkr evidence --frameworks ... --json` and `wrkr report --json`, and compare the updated `framework_coverage` plus report summary guidance.

### Unsafe output-path handling

If output directory is non-empty and not Wrkr-managed, evidence fails closed with exit `8` and `unsafe_operation_blocked`.

## Verify workflow

```bash
wrkr verify --chain --json
```

Check `chain.intact` and `chain.head_hash`.

## Regress workflow

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --summary-md --summary-md-path ./.tmp/regress-summary.md --template operator --json
```

Use exit `5` and drift reasons as gate criteria.
For attack-path divergence above thresholds, expect one summarized `critical_attack_path_drift` reason with nested `attack_path_drift` details (`added`, `removed`, `score_changed`, counts, thresholds).

## Identity lifecycle workflow

```bash
wrkr identity list --json
wrkr identity show <agent_id> --json
wrkr identity approve <agent_id> --approver @maria --scope read-only --expires 90d --json
wrkr identity deprecate <agent_id> --reason "tool retired" --json
wrkr identity revoke <agent_id> --reason "policy violation" --json
wrkr lifecycle --org local --summary-md --summary-md-path ./.tmp/lifecycle-summary.md --template audit --json
```

Use lifecycle transitions and proof-chain history to track approval and revocation.

## Scenario references (Tier 11)

- FR11: policy checks
- FR12: profile compliance
- FR13: posture score

Reference scenario suites in `internal/scenarios/` and coverage mapping in `internal/scenarios/coverage_map.json`.
