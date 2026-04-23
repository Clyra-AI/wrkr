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

For the current public launch, the recommended first path is the hosted org posture flow below when hosted prerequisites are ready. If they are not, use the curated scenario fallback and then return to the org path once GitHub access is configured.
When concrete local tool, MCP, or secret signals exist, `scan --my-setup --json` also emits additive `activation.items` so the local-machine path stays concrete without mutating the raw risk ranking.

```bash
# Hosted org posture first when prerequisites are ready
wrkr init --non-interactive --org acme --github-api https://api.github.com --json
wrkr scan --config ~/.wrkr/config.json --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr verify --chain --json

# Low or zero first-run framework_coverage means the current state is evidence sparse, not that parsing is broken

# Evaluator-safe scenario fallback when hosted prerequisites are not ready yet
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/wrkr-scenario-evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --json

# If hosted prerequisites are still not ready yet, use a deterministic local fallback
wrkr scan --path ./your-repo --json
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
wrkr inventory approve <agent-id> --owner platform-security --evidence SEC-123 --expires 90d --state ./.wrkr/last-scan.json --json
```

`wrkr evidence` now fails closed when the saved proof chain is malformed or tampered, and `wrkr verify --chain --json` remains the explicit machine gate for integrity.
Inventory approval/evidence mutations are local, file-based, and append proof events. Evidence and verify JSON may include additive `control_evidence` so operators can see existing and missing proof for active backlog controls.
The hosted org path is the primary launch workflow when prerequisites are ready. Use the curated scenario when you want the evaluator-safe fallback because it avoids repo-root fixture noise from Wrkr's own scenarios, docs, and test fixtures. That scenario path is the canonical `repo_set` example for `--path`: Wrkr scans the immediate child repos in the bundle instead of treating the bundle root as one repo.
Use `wrkr scan --path ./your-repo --json` when the selected directory itself is the repo root and carries repo-root signals such as `.git`, `go.mod`, `AGENTS.md`, or `.codex/`. Use a bundle root like `./scenarios/wrkr/scan-mixed-org/repos` when you want immediate child repos scanned as a deterministic repo-set.

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
