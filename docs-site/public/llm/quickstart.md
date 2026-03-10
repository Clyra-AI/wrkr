# Wrkr Quickstart

`wrkr scan --my-setup --json` is the zero-integration first-value path for developer-machine hygiene. Hosted `--repo` and `--org` scans require explicit GitHub API configuration.

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
wrkr scan --github-org acme --github-api https://api.github.com --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --json
```

Use these next when you want compliance handoff:

- `wrkr report --top 5 --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json`
- `wrkr verify --chain --json`
- `wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --json`

Low or zero `framework_coverage` on a first run means the scanned state still lacks documented controls or approvals. It is an evidence gap, not a parser failure.

Use these intent guides next:

- `/docs/examples/personal-hygiene/`
- `/docs/examples/security-team/`
- `/docs/intent/scan-org-repos-for-ai-agents-configs/`
- `/docs/intent/detect-headless-agent-risk/`
- `/docs/intent/generate-compliance-evidence-from-scans/`
- `/docs/intent/gate-on-drift-and-regressions/`
