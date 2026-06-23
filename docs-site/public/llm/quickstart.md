# Wrkr Quickstart

Install with Homebrew or the pinned Go path first, then verify the installed CLI:

```bash
brew install Clyra-AI/tap/wrkr
WRKR_VERSION="v1.10.0"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
wrkr version --json

# Optional convenience latest path (secondary)
go install github.com/Clyra-AI/wrkr/cmd/wrkr@latest
wrkr version --json
```

For the current public launch, the shortest first path is: scan one repo, render
the focused Agent Action BOM, and review the top workflow path. Use the hosted
org posture flow below when you need shared inventory or broader audit handoff.
When concrete local tool, MCP, or secret signals exist, `scan --my-setup --json` also emits additive `activation.items` so the local-machine path stays concrete without mutating the raw risk ranking.
For manual large scans, keep `--state` plus the generated markdown/evidence artifacts as the durable handoff and reserve `--json` for automation and CI.

Choose one explicit first-value path:

- Focused repo review first when you want the top workflow BOM immediately.
- Hosted org posture when GitHub access is ready.
- Evaluator-safe scenario when you are evaluating Wrkr itself or hosted prerequisites are not ready yet.
- Developer-machine hygiene when you want local MCP and tool posture first.

```bash
# Focused repo review first
wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scan-summary.md
wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --md --md-path ./.tmp/focused-agent-action-bom.md
wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --evidence-json --evidence-json-path ./.tmp/focused-agent-action-bom-evidence.json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
wrkr assess --path ./your-repo --output-dir ./.wrkr/design-partner-assessment --baseline ./.wrkr/wrkr-regress-baseline.json --template design-partner-summary --share-profile design-partner --ticket-format jira

# Hosted org posture first when prerequisites are ready
wrkr init --non-interactive --org acme --github-api https://api.github.com
wrkr scan --config ~/.wrkr/config.json --state ./.wrkr/last-scan.json --timeout 30m --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence
wrkr verify --chain --state ./.wrkr/last-scan.json

# Low or zero first-run framework_coverage means the current state is evidence sparse, not that parsing is broken

# Evaluator-safe scenario fallback when hosted prerequisites are not ready yet
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scenario-summary.md
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/wrkr-scenario-evidence
wrkr verify --chain --state ./.wrkr/last-scan.json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json

# If hosted prerequisites are still not ready yet, use a deterministic local fallback
wrkr scan --path ./your-repo --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scan-summary.md
wrkr scan --my-setup --state ./.wrkr/last-scan.json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
wrkr inventory approve <agent-id> --owner platform-security --evidence SEC-123 --expires 90d --state ./.wrkr/last-scan.json --json
```

Automation / CI equivalent:

```bash
wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --json --json-path ./.wrkr/scan.json
wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr assess --path ./your-repo --output-dir ./.wrkr/assessment --json
```

`wrkr evidence` now fails closed when the saved proof chain is malformed or tampered, and `wrkr verify --chain --json` remains the explicit machine gate for integrity.
`summary.repeat_usage_signals` and `agent_action_bom.summary.repeat_usage_signals`
count only local artifact families such as baselines, assess reruns, evidence
exports, ticket exports, and action-contract exports; they do not serialize raw
paths, owner names, prompts, or private URLs.
Inventory approval/evidence mutations are local, file-based, and append proof events. Evidence and verify JSON may include additive `control_evidence` so operators can see existing and missing proof for active backlog controls.
The hosted org path is the primary launch workflow when prerequisites are ready. Use the curated scenario when you want the evaluator-safe fallback because it avoids repo-root fixture noise from Wrkr's own scenarios, docs, and test fixtures. That scenario path is the canonical `repo_set` example for `--path`: Wrkr scans the immediate child repos in the bundle instead of treating the bundle root as one repo.
The curated scenario is intentionally risky by design, so a low posture score or low first-run `framework_coverage` is expected and useful during evaluation.
Use `wrkr scan --path ./your-repo --state ./.wrkr/last-scan.json` when the selected directory itself is the repo root and carries repo-root signals such as `.git`, `go.mod`, `AGENTS.md`, or `.codex/`. Use a bundle root like `./scenarios/wrkr/scan-mixed-org/repos` when you want immediate child repos scanned as a deterministic repo-set.

Use these next when you want deeper triage:

- `wrkr report --top 5 --json`
- `wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json`

`wrkr verify --chain --json` now reports whether the result was structural-only (`chain_only` / `unavailable`) or authenticated (`chain_and_attestation` or `chain_and_signature` with `verified` authenticity status).
Resumed hosted org scans also revalidate checkpoint files and reused materialized repo roots before detector execution, so symlink-swapped resume state is blocked as unsafe.

Low or zero `framework_coverage` on a first run means the scanned state still lacks documented controls or approvals. It is an evidence gap, not a parser failure, and `wrkr evidence --json` also emits additive `coverage_note` guidance with the same interpretation.

Use these intent guides next:

- `/docs/examples/personal-hygiene/`
- `/docs/examples/security-team/`
- `/docs/commands/`
- `/docs/intent/scan-org-repos-for-ai-agents-configs/`
- `/docs/intent/detect-headless-agent-risk/`
- `/docs/intent/generate-compliance-evidence-from-scans/`
- `/docs/intent/gate-on-drift-and-regressions/`
