# Wrkr Quickstart

For the current public launch, the recommended first path is security/platform org posture and evidence. `wrkr scan --my-setup --json` remains the zero-integration secondary path for developer-machine hygiene.
When concrete local tool, MCP, or secret signals exist, `scan --my-setup --json` also emits additive `activation.items` so the local-machine path stays concrete without mutating the raw risk ranking.

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr verify --chain --json
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

Use these next when you want deeper triage:

- `wrkr report --top 5 --json`
- `wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json`

`wrkr verify --chain --json` now reports whether the result was structural-only (`chain_only` / `unavailable`) or authenticated (`chain_and_attestation` or `chain_and_signature` with `verified` authenticity status).

Low or zero `framework_coverage` on a first run means the scanned state still lacks documented controls or approvals. It is an evidence gap, not a parser failure.

Use these intent guides next:

- `/docs/examples/personal-hygiene/`
- `/docs/examples/security-team/`
- `/docs/commands/`
- `/docs/intent/scan-org-repos-for-ai-agents-configs/`
- `/docs/intent/detect-headless-agent-risk/`
- `/docs/intent/generate-compliance-evidence-from-scans/`
- `/docs/intent/gate-on-drift-and-regressions/`
