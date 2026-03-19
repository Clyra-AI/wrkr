# Wrkr Quickstart

Install with Homebrew or the pinned Go path first, then verify the installed CLI:

```bash
brew install Clyra-AI/tap/wrkr
WRKR_VERSION="v1.0.0"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
wrkr version --json

# Optional convenience latest path (secondary)
go install github.com/Clyra-AI/wrkr/cmd/wrkr@latest
wrkr version --json
```

For the current public launch, the recommended first path is security/platform org posture and evidence. `wrkr scan --path ./your-repo --json` and `wrkr scan --my-setup --json` remain the zero-integration fallback paths when hosted setup is not ready yet.
When concrete local tool, MCP, or secret signals exist, `scan --my-setup --json` also emits additive `activation.items` so the local-machine path stays concrete without mutating the raw risk ranking.

```bash
# Hosted prerequisites: set --github-api and usually a GitHub token for private repos or rate limits
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr verify --chain --json
wrkr scan --path ./your-repo --json
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
