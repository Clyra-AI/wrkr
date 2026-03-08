# Wrkr Quickstart

`wrkr scan --path ...` is the zero-integration first-value path. Hosted `--repo` and `--org` scans require explicit GitHub API configuration.

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --json
wrkr report --top 5 --json
wrkr score --json
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
wrkr verify --chain --json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

Low or zero `framework_coverage` on a first run means the scanned state still lacks documented controls or approvals. It is an evidence gap, not a parser failure.

Use these intent guides next:

- `/docs/intent/scan-org-repos-for-ai-agents-configs/`
- `/docs/intent/detect-headless-agent-risk/`
- `/docs/intent/generate-compliance-evidence-from-scans/`
- `/docs/intent/gate-on-drift-and-regressions/`
