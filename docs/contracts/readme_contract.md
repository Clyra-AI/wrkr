# Cross-Repo README Contract (Wrkr Variants)

This document defines the currently supported README contract variants across Wrkr, Proof, and Gait.

Wrkr is transitioning to a landing-page-first README model while Proof and Gait still track the classic shared model. Both variants are valid only when their non-README source-of-truth obligations are met.

## Supported variants

### Variant A: Shared README Classic

Required sections:

1. Install
2. First 10 Minutes
3. Integration
4. Command Surface
5. Governance and Support

Section requirements:

- Install
  - Include at least one pinned install path.
  - Include minimal-dependency guidance (no hidden mandatory helpers).
  - Include verification command(s) after install.
- First 10 Minutes
  - Foreground the developer-machine path before the org/audit path.
  - Include the copy-paste sequence `wrkr scan --my-setup`, `wrkr mcp-list`, `wrkr scan --github-org`, `wrkr inventory --diff`.
  - Show deterministic `--json` command anchors.
  - Include one concrete personal-setup output example with realistic privilege findings.
  - Link to canonical state lifecycle behavior.
- Integration
  - Provide CI-adoption workflow and gate semantics.
  - Clarify standalone usage vs optional ecosystem integrations.
  - Link to deeper integration docs.
- Command Surface
  - Enumerate stable command families.
  - Reference JSON/exit-code contract expectations.
- Governance and Support
  - Link contributing, security policy, code of conduct, changelog, and issue workflows.
  - Include docs source-of-truth guidance.

### Variant B: Wrkr Landing v2

Required sections:

1. Install
2. Start Here
3. Why Wrkr
4. What You Get
5. What Wrkr Detects
6. What Wrkr Does Not Do
7. Works With Gait
8. Typical Workflows
9. Command Surface
10. Output And Contracts
11. Security And Privacy
12. Learn More

Section requirements:

- Install
  - Include Homebrew and a pinned/reproducible Go install path on the first screen.
  - Include `wrkr version` verification on the first screen.
  - README may keep a convenience `@latest` Go install path only if it is explicitly secondary to the pinned path.
  - Pinned/reproducible install guidance must remain canonical in `docs/install/minimal-dependencies.md`.
- Start Here
  - Make the current launch persona explicit at the top of the section.
  - For the current Wrkr launch, foreground the security/platform-led org posture workflow.
  - If an evaluator-safe scenario is shown, present it as an explicit fallback/demo path after the hosted org posture workflow rather than as the primary launch path.
  - Keep developer-machine hygiene as the secondary path.
  - Place hosted prerequisites (`--github-api` and token guidance) adjacent to the first hosted org workflow.
  - If `wrkr init` is used for hosted onboarding, keep it immediately adjacent to the first hosted scan command and make the `wrkr scan --config ...` follow-on path explicit.
  - Include explicit deterministic fallback commands before hosted setup can dead-end (`wrkr scan --path` and/or `wrkr scan --my-setup`).
  - Explain the dual `wrkr scan --path` contract: repo-root fallback for one selected repo, and bundle-root repo-set behavior for paths such as `./scenarios/wrkr/*/repos`.
  - Include `wrkr scan --my-setup`, `wrkr mcp-list`, and `wrkr inventory --diff`.
  - Include `wrkr init`, `wrkr scan --github-org` or `wrkr scan --config ...`, `wrkr evidence`, and `wrkr verify` when security/platform-led launch copy is used.
  - Keep deterministic `--json` command anchors.
  - Show one personal-setup output example and one org-scan output example.
  - Clarify that environment-key presence and source bookkeeping remain finding-only signals, not approvable lifecycle identities.
- Why Wrkr / What You Get / What Wrkr Detects / What Wrkr Does Not Do
  - Keep scope truthful to deterministic repo/config/CI plus local-machine discovery.
  - Preserve explicit non-goals such as no live MCP probing by default and no LLMs in scan/risk/proof paths.
  - State that local path scans stay bounded to the selected repo root and reject root-escaping symlinked config/env/workflow/MCP files with explicit diagnostics.
- Works With Gait
  - Clarify Wrkr vs Gait boundary without making Gait a requirement to run Wrkr.
- Typical Workflows / Command Surface / Output And Contracts
  - Preserve stable command families, `--json`, SARIF, and exit-code expectations.
- Learn More
  - Link to `docs/commands/`, `docs/examples/`, and deeper positioning/workflow docs.

## Non-README obligations for Variant B

- `docs/install/minimal-dependencies.md` and `docs/trust/release-integrity.md` remain the install/release contract anchors.
- Docs source-of-truth guidance lives in `docs/map.md` and `docs/README.md`, not necessarily in `README.md`.
- OSS trust/support discoverability may live in canonical docs/docs-site surfaces instead of the README footer, but it must remain explicit and validated.

## Validation

Run:

```bash
go test ./testinfra/hygiene -count=1
make test-docs-consistency
make test-docs-storyline
```
