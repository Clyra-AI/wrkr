# wrkr report

## Synopsis

```bash
wrkr report [--json] [--explain] [--md] [--md-path <path>] [--pdf] [--pdf-path <path>] [--evidence-json] [--evidence-json-path <path>] [--csv-backlog] [--csv-backlog-path <path>] [--template exec|operator|audit|public|ciso|appsec|platform|customer-draft] [--share-profile internal|public] [--baseline <path>] [--previous-state <path>] [--top <n>] [--state <path>]
```

## Flags

- `--json`
- `--explain`
- `--md`
- `--md-path`
- `--pdf`
- `--pdf-path`
- `--evidence-json`
- `--evidence-json-path`
- `--csv-backlog`
- `--csv-backlog-path`
- `--template`
- `--share-profile`
- `--baseline`
- `--previous-state`
- `--top`
- `--state`

## Example

```bash
wrkr report --md --md-path ./.tmp/wrkr-summary.md --template operator --share-profile internal --json
wrkr report --pdf --pdf-path ./.tmp/wrkr-summary.pdf --template exec --json
wrkr report --md --md-path ./.tmp/wrkr-summary-public.md --template public --share-profile public --json
wrkr report --template ciso --md --md-path ./.tmp/ciso.md --pdf --pdf-path ./.tmp/ciso.pdf --evidence-json --evidence-json-path ./.tmp/evidence.json --csv-backlog --csv-backlog-path ./.tmp/backlog.csv --json
```

## Behavior contract

wrkr report renders deterministic summaries from saved scan state without changing JSON or exit-code contracts.
wrkr report --pdf writes a deterministic PDF artifact with wrapped, paginated executive-summary output; the board-ready claim is acceptance-backed by explicit executive report fixtures.

Expected JSON keys: `status`, `generated_at`, `top_findings`, `attack_paths`, `top_attack_paths`, additive `action_paths`, additive `action_path_to_control_first`, additive `assessment_summary`, additive `exposure_groups`, `total_tools`, `tool_type_breakdown`, `compliance_gap_count`, `compliance_summary`, `summary`, `md_path`, `pdf_path`, additive `evidence_json_path`, additive `backlog_csv_path`, and additive `artifact_paths`.
`assessment_summary` is additive at the top level and under `summary` when govern-first action paths are present; it leads with governable-path counts, the top path to control first, the strongest identity-backed path, additive `ownerless_exposure` counts, additive `identity_exposure_summary`, additive `identity_to_review_first` / `identity_to_revoke_first`, and the saved proof-chain path.
`summary.attack_paths` provides deterministic attack-path section metadata (`total`, `top_path_ids`) used in report templates and external appendix joins.
`compliance_summary.frameworks[*].controls[*]` exposes additive framework/control/article rollups with deterministic `finding_count`, `mapped_rule_ids`, and coverage status.
`summary.compliance_summary` mirrors the same machine-readable contract used by report markdown/PDF generation.
When the saved scan target is `my_setup`, `summary.activation` exposes the same additive concrete-first activation view used by the local-machine scan flow.
When the saved scan target is `org` or `path`, `summary.activation` exposes the additive govern-first candidate path view used by the scan flow.
`summary.action_paths` and top-level `action_paths` expose the ranked govern-first path objects, including additive delivery-chain fields such as `pull_request_write`, `merge_execute`, `deploy_write`, `delivery_chain_status`, and `production_target_status`, ownership/governance fields such as `operational_owner`, `owner_source`, `ownership_status`, and `approval_gap_reasons`, additive execution-identity fields such as `execution_identity`, `execution_identity_type`, `execution_identity_source`, `execution_identity_status`, and `execution_identity_rationale`, and additive path-semantics fields such as `business_state_surface`, `shared_execution_identity`, and `standing_privilege`. `summary.action_path_to_control_first` / top-level `action_path_to_control_first` expose one prioritized path with deterministic summary counts.
`summary.action_paths[*].path_id` and `summary.action_path_to_control_first.path.path_id` remain opaque deterministic identifiers currently emitted in `apc-<hex>` form. Use them as stable join keys only; consumers must not parse business meaning from the string.
`summary.exposure_groups` and top-level `exposure_groups` provide additive grouped exposure clusters on top of raw `action_paths`; they preserve `path_ids` for drill-down while summarizing repeated paths by repo, tool, execution identity, delivery-chain status, and business-state surface.
`summary.top_risks` becomes path-first when govern-first `action_paths` exist, but the raw `top_findings` payload remains unchanged for operators and automation.
Customer-ready templates `ciso`, `appsec`, `platform`, `audit`, and `customer-draft` lead with `summary.control_backlog` and render the control backlog before raw risk/finding sections in Markdown/PDF. `customer-draft` forces the public share profile and redacts sensitive local paths, repos, owners, proof paths, and ownership evidence. `--csv-backlog` writes a deterministic CSV with owner, evidence, recommended action, SLA, and closure criteria columns. `--evidence-json` writes a deterministic JSON evidence bundle led by the control backlog.
`summary.security_visibility` exposes additive reference-basis and `unknown_to_security` counts sourced from the saved scan state.
When the saved scan state does not carry a usable `reference_basis`, report output suppresses `unknown_to_security` claims and surfaces `reference_basis unavailable` wording instead.
`wrkr report` renders from saved scan state only. It summarizes static posture, risky write paths, and proof artifacts; it does not claim live runtime observation or control-layer enforcement.
Manual `identity` and `inventory` approvals refresh the saved backlog, action-path posture, and posture score in place, so `wrkr report --state <path> --json` reflects those decisions without a rescanning step.

Public template behavior (`--template public --share-profile public`):

- `summary.section_order` starts with headline then methodology.
- `summary.methodology` includes machine-readable reproducibility metadata (`wrkr_version`, scan window, repo/file counts, command set, and exclusion criteria).
- when production targets are not configured, public/report wording stays at `write_capable` and reports production-target status rather than a production-write count.
- when saved-state security visibility lacks a usable reference basis, public/report wording suppresses `unknown_to_security` counts instead of fabricating them.
- share-profile redaction is applied to public-facing risk/proof fields.

`--explain` emits short deterministic compliance mapping lines sourced from the same `compliance_summary` payload.
When current findings do not yet map to bundled controls, the explain/report summary says bundled framework mappings are available and that current coverage still reflects only evidence present in the saved scan state.

## Coverage semantics

Report compliance/posture values are derived from evidence present in the current scan state.

- Low compliance/coverage in report output indicates control evidence gaps in the scanned snapshot.
- Low compliance/coverage does not imply Wrkr lacks framework support.
- Use report findings as remediation priorities, then remediate gaps, rerun deterministic scan/evidence/report commands, and confirm improvement from the updated evidence state.
