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
  - Include Homebrew and Go install paths.
  - README may use a convenience `@latest` Go install path.
  - Pinned/reproducible install guidance must remain canonical in `docs/install/minimal-dependencies.md`.
- Start Here
  - Foreground developer local-machine workflow before the org/security-team workflow.
  - Include `wrkr scan --my-setup`, `wrkr mcp-list`, and `wrkr inventory --diff`.
  - Keep deterministic `--json` command anchors.
  - Show one personal-setup output example and one org-scan output example.
- Why Wrkr / What You Get / What Wrkr Detects / What Wrkr Does Not Do
  - Keep scope truthful to deterministic repo/config/CI plus local-machine discovery.
  - Preserve explicit non-goals such as no live MCP probing by default and no LLMs in scan/risk/proof paths.
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
make test-docs-consistency
make test-docs-storyline
```
