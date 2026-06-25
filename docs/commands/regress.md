# wrkr regress

## Subcommands

```bash
wrkr regress init --baseline <scan-state-path> [--output <baseline-path>] [--json]
wrkr regress run --baseline <baseline-path-or-scan-state-path> [--state <state-path>] [--summary-md] [--summary-md-path <path>] [--template exec|operator|audit|public|ciso|appsec|platform|customer-draft|agent-action-bom|design-partner-summary] [--share-profile internal|public|customer-redacted|design-partner|external-redacted|investor-safe] [--top <n>] [--json]
```

## Flags

### regress init

- `--json`
- `--baseline`
- `--output`

### regress run

- `--json`
- `--baseline`
- `--state`
- `--summary-md`
- `--summary-md-path`
- `--template`
- `--share-profile`
- `--top`

## Example

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --summary-md --summary-md-path ./.tmp/regress-summary.md --template operator --json
```

Compatibility example using a raw saved scan snapshot baseline:

```bash
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

Expected JSON keys include `status`, `baseline_path`, `tool_count` (init) and drift fields plus optional `summary_md_path` (run). `wrkr regress run --json` now also carries additive `comparison_status`, `comparison_issues[]`, `drift_category_count`, and `drift_categories[]` so recurring reviews can distinguish clean comparisons from unavailable or incomplete action-path drift review.
Saved scan state must be complete. `wrkr regress init` rejects incomplete baseline scan snapshots, and `wrkr regress run` rejects incomplete current state or raw saved-scan baselines carrying `partial_result`, `source_errors`, or `source_degraded` with `invalid_input` (exit `6`).
Baseline `tools[*]` continue to expose `agent_id` and `tool_id`; additive `agent_instance_id` is now included when instance-scoped identity is available.
Baseline `tools[*]` may also include additive approved control-path state: `security_visibility`, `owner`, `evidence_expires`, `write_path_classes`, `secret_bearing`, `confidence`, `control_path_type`, `repo`, `location`, and `risk_score`.
Captured `action_paths[*]` in the regress baseline now also preserve additive review-loop comparison fields such as `review_lifecycle_state`, `previous_review_lifecycle_state`, `resolved_visibility`, `reopen_state`, `reopen_reasons`, `review_scope`, `review_valid_until`, `config_fingerprint`, and imported/declaration evidence refs so recurring customer review decisions reopen only on material drift.
`wrkr regress init` reads the saved scan snapshot directly, so approvals recorded with `wrkr identity` or `wrkr inventory` become visible in newly generated baselines without requiring a follow-up scan.
Drift `reasons[*]` continue to expose `agent_id`/`tool_id` and now include additive `agent_instance_id` when the current state carries instance-scoped identity.
Deprecated or revoked tools that reappear in current scan state produce deterministic `deprecated_tool_reappeared` or `revoked_tool_reappeared` drift reasons.
When critical attack-path sets diverge above deterministic thresholds, `reasons` includes a single `critical_attack_path_drift` summary entry with machine-readable `attack_path_drift` details (`added`, `removed`, `score_changed`).
Regress baselines and drift comparison operate on lifecycle-bearing real tool identities only. Finding-only signals such as `secret_presence`, `source_discovery`, `policy_*`, and `parse_error` stay in findings/risk output and do not create `new_unapproved_tool` drift on their own.

Action-path drift categories are additive and stable:

- `new_write_paths`
- `new_deploy_paths`
- `new_credentials`
- `new_unknown_approval_evidence`
- `resolved_gaps`
- `worsened_paths`
- `new_contradictions`
- `paths_ready_for_control`
- `removed_paths`
- `changed_authority`
- `changed_evidence`
- `changed_target_class`

Each `drift_categories[*]` row includes severity, priority, stable current/baseline path refs, additive evidence refs, buyer-facing examples, and recommended next actions. Legacy `reasons[*]` remain present for lifecycle, approval-expiry, owner-change, permission-expansion, and critical attack-path contracts.
Action-path drift review stays additive and deterministic: benign report ordering does not reopen resolved paths, while expiry, contradiction, disappeared imported controls, credential-family changes, and target-class escalation show up through the same stable path matching and evidence refs without forcing scan/report commands to fail as runtime errors.

When a legacy regress baseline lacks captured action-path comparison data, Wrkr now fails closed with `comparison_status=baseline_action_paths_unavailable` instead of silently emitting a clean no-drift result. Regenerate the baseline from a current `wrkr scan --state ... --json` snapshot or `wrkr regress init` artifact before relying on drift-review output.
The canonical baseline artifact (`.wrkr/wrkr-regress-baseline.json`) and any generated drift artifacts are also counted by later `summary.repeat_usage_signals` / `agent_action_bom.summary.repeat_usage_signals` surfaces when you rerun `report` or `assess` in the same working area.

Compatibility note:

- `wrkr inventory` is the developer-facing wrapper for deterministic added/removed/changed inventory review from scan state.
- `wrkr regress run` accepts either a `wrkr regress init` artifact or a raw saved scan snapshot. The `regress init` artifact remains the canonical path for CI and policy workflows.
- `v1` baselines created before instance identities are automatically reconciled against equivalent current identities at the same legacy anchor. Additional current instances beyond that legacy match still drift normally.

Canonical state/baseline path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).
