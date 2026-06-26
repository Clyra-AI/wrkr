# wrkr export

## Synopsis

```bash
wrkr export [--format inventory|appendix] [--anonymize] [--csv-dir <path>] [--state <path>] [--json]
wrkr export tickets --top <n> --format jira|github|servicenow --dry-run --state <path> --json
wrkr export declarations --state <path> (--resolution-key <rk>|--path-id <id>|--backlog-id <id>) [--action <closure_action>] [--mode repo_local|governance_repo] [--share-profile <profile>] [--patch-path <path>] [--json]
```

## Flags

- `--json`
- `--format`
- `--anonymize`
- `--csv-dir` (appendix only)
- `--state`
- `tickets --top`
- `tickets --format`
- `tickets --dry-run`
- `declarations --resolution-key`
- `declarations --path-id`
- `declarations --backlog-id`
- `declarations --action`
- `declarations --mode`
- `declarations --share-profile`
- `declarations --patch-path`

## Example

```bash
wrkr export --format inventory --json
wrkr export --format inventory --anonymize --json
wrkr export --format appendix --csv-dir ./.tmp/appendix --json
wrkr export tickets --top 10 --format jira --dry-run --state ./.wrkr/last-scan.json --json
wrkr export declarations --state ./.wrkr/last-scan.json --resolution-key rk-release --action accept_risk_with_expiry --json
wrkr export declarations --state ./.wrkr/last-scan.json --resolution-key rk-release --action declare_repo_owner --mode governance_repo --patch-path ./declaration-patch.yaml --json
```

Inventory format JSON keys: `export_version`, `exported_at`, `org`, `agents`, `tools`.
Appendix format JSON keys: `status`, `appendix`, optional `csv_files`.
Ticket export JSON keys: `ticket_export_version`, `format`, `dry_run`, `tickets`.

Saved scan state must be complete. If `--state` carries `partial_result`, `source_errors`, or `source_degraded`, inventory, appendix, and ticket exports return `invalid_input` (exit `6`) before writing derived output.

Compatibility note:

- `wrkr inventory --json` is a developer-facing wrapper over `wrkr export --format inventory --json`.
- `export --format inventory` remains the stable raw export contract for automation and archival workflows.

Appendix export emits deterministic table sets for:

- `inventory_rows`
- `privilege_rows`
- `approval_gap_rows`
- `regulatory_rows`

`approval_gap_rows` remains a compatibility appendix name. The underlying path objects and report artifacts now lead with canonical evidence-state fields such as `approval_evidence_state`, `control_resolution_state`, and `proof_evidence_state`.
Accepted-risk and suppression handling remain visible in saved backlog/ticket payloads; Wrkr does not delete appendix evidence just because an item is under accepted-risk review.
Appendix export is complementary to the focused Agent Action BOM path view: the report command can answer one workflow/action path first, while `wrkr export --format appendix` keeps the broader row-level audit tables available for offline joins and CSV workflows.

Ticket export is offline-first. `wrkr export tickets --dry-run --json` consumes the saved `control_backlog`; it does not run detectors and does not call Jira, GitHub Issues, or ServiceNow APIs. Unsupported ticket formats fail with `invalid_input` and exit `6`. Send/adaptor execution is a future explicit opt-in surface and should fail closed when credentials are missing.
Declaration export is also offline-first. It rebuilds the saved Agent Action BOM and control backlog locally, selects one declaration-capable `closure_action`, validates the generated YAML against the declaration schema, and either prints the snippet or writes a safe local patch artifact. Unsafe patch output paths fail closed with `unsafe_operation_blocked` and exit `8`.
Repo-local declaration mode targets `.wrkr/control-declarations.yaml`. Governance-repo mode targets `wrkr-control-declarations.yaml` and keeps repo scope explicit when the snippet needs to be portable across many repositories. Shareable profiles never leak internal repo/path identifiers in generated snippets; when pseudonymized inputs cannot produce a directly applicable declaration, the JSON payload carries `directly_applicable=false` plus deterministic warnings.

Each ticket includes owner, repo, path, control-path type, capability, evidence, recommended action, SLA, closure criteria, confidence, proof requirements, and deterministic `security_test_recipes` when risky control paths need validation. Recipes cover prompt injection, MCP endpoint swaps, egress attempts, destructive-action dry runs, untrusted repo content, and secret-scope validation using dry-run or sandbox preconditions. When the saved backlog item is linked to the additive governance graph, ticket payloads may also carry stable control-path node/edge references and typed `credential_provenance` context so downstream systems can preserve the same operator review thread without parsing raw workflow details.
