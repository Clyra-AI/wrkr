# wrkr export

## Synopsis

```bash
wrkr export [--format inventory|appendix] [--anonymize] [--csv-dir <path>] [--state <path>] [--json]
wrkr export tickets --top <n> --format jira|github|servicenow --dry-run --state <path> --json
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

## Example

```bash
wrkr export --format inventory --json
wrkr export --format inventory --anonymize --json
wrkr export --format appendix --csv-dir ./.tmp/appendix --json
wrkr export tickets --top 10 --format jira --dry-run --state ./.wrkr/last-scan.json --json
```

Inventory format JSON keys: `export_version`, `exported_at`, `org`, `agents`, `tools`.
Appendix format JSON keys: `status`, `appendix`, optional `csv_files`.
Ticket export JSON keys: `ticket_export_version`, `format`, `dry_run`, `tickets`.

Compatibility note:

- `wrkr inventory --json` is a developer-facing wrapper over `wrkr export --format inventory --json`.
- `export --format inventory` remains the stable raw export contract for automation and archival workflows.

Appendix export emits deterministic table sets for:

- `inventory_rows`
- `privilege_rows`
- `approval_gap_rows`
- `regulatory_rows`

Ticket export is offline-first. `wrkr export tickets --dry-run --json` consumes the saved `control_backlog`; it does not run detectors and does not call Jira, GitHub Issues, or ServiceNow APIs. Unsupported ticket formats fail with `invalid_input` and exit `6`. Send/adaptor execution is a future explicit opt-in surface and should fail closed when credentials are missing.

Each ticket includes owner, repo, path, control-path type, capability, evidence, recommended action, SLA, closure criteria, confidence, proof requirements, and deterministic `security_test_recipes` when risky control paths need validation. Recipes cover prompt injection, MCP endpoint swaps, egress attempts, destructive-action dry runs, untrusted repo content, and secret-scope validation using dry-run or sandbox preconditions. When the saved backlog item is linked to the additive governance graph, ticket payloads may also carry stable control-path node/edge references and typed `credential_provenance` context so downstream systems can preserve the same operator review thread without parsing raw workflow details.
