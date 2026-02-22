# PLAN Wrkr Docs-Site: Agent-Answerability First Documentation System

Date: 2026-02-22
Source of truth: `product/wrkr.md`, `product/dev_guides.md`, `AGENTS.md`, and validated baseline from `/Users/davidahmann/Projects/gait/docs` + `/Users/davidahmann/Projects/gait/docs-site`
Scope: Wrkr OSS docs corpus and docs-site only. No Axym/Gait feature implementation in Wrkr runtime.

## Global Decisions (Locked)

- One-liner is canonical and repeated across core surfaces:
  - "Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready."
- Agent answerability is primary objective; human SEO is secondary.
- Command-first claims only:
  - every high-intent page must include exact CLI commands, expected JSON keys, exit codes, and sample outputs.
- Deterministic truth over marketing:
  - publish what Wrkr detects, what it does not detect, deterministic guarantees, and explicit "when not to use Wrkr".
- Docs-site architecture follows Gait pattern:
  - static Next.js export, markdown ingestion, stable URLs, sitemap/robots/AI sitemap/llms surfaces.
- Visual system should preserve Gait-style UX direction:
  - dark gradient base, cyan/blue accent, high-contrast code blocks, clear hierarchy, mobile-first responsive behavior.
- Docs contracts are merge-gated:
  - docs CLI parity, docs storyline/smoke, docs-site build, link validation, and discoverability checks are required.
- Any changes to CLI flags, exit codes, schemas, or risk semantics must update docs in same PR.

## Current Baseline (Observed)

- Wrkr docs exist and are command-focused:
  - `docs/commands/*.md`, `docs/examples/*.md`, `docs/specs/wrkr-manifest.md`.
- Wrkr has deterministic docs checks today:
  - `scripts/check_docs_cli_parity.sh`, `scripts/check_docs_storyline.sh`, `scripts/run_docs_smoke.sh`.
- Wrkr has no docs-site app directory and no publish pipeline:
  - no `docs-site/`, no docs GitHub Pages workflow.
- Wrkr has no agent-discovery surfaces:
  - no `llms.txt`, `llms-full.txt`, `/llm/*.md`, `ai-sitemap.xml`, `robots.txt`.
- Wrkr docs are not frontmatter-standardized yet:
  - no YAML frontmatter in current docs markdown set.
- Gait reference baseline is stronger:
  - complete docs-site scaffold, LLM context hub, JSON-LD, sitemap/robots/AI sitemap, and docs consistency gating.

## Exit Criteria

1. Wrkr has a built and linted static docs-site under `docs-site/` with GitHub Pages deployment workflow.
2. Canonical one-liner appears in README, docs quickstart, docs-site homepage, `llms.txt`, and `llm/product.md`.
3. Four high-intent pages ship with command-first, verifiable sections:
  - scan org repos
  - detect headless risk
  - generate compliance evidence
  - gate on drift/regressions.
4. Agent/crawler surfaces are live and consistent:
  - `llms.txt`, `llms-full.txt`, `llm/*.md`, `sitemap.xml`, `ai-sitemap.xml`, `robots.txt`, `/llms`.
5. Trust-index pages exist and are discoverable from nav/docs home:
  - deterministic guarantees, detection coverage matrix, proof-chain docs, schema/contracts, security/privacy posture, release integrity.
6. Docs checks fail closed on drift:
  - missing one-liner, missing required intent pages, missing required command/exit-code tokens, sitemap/nav mismatch.
7. CI runs docs-site lint/build + docs consistency + docs smoke in PR/main/release lanes.
8. All new pages are chunk-friendly:
  - stable slug, short sections, heading structure, and frontmatter.

## Recommendation Traceability

| Recommendation | Planned Coverage |
|---|---|
| Own the query in one sentence everywhere | Story 1.1, Story 2.1, Story 6.1 |
| Create intent pages agents can quote | Story 2.2, Story 3.1 |
| Use command-first, verifiable docs | Story 3.1, Story 3.2, Story 6.2 |
| Publish deterministic benchmarks/comparisons + when not to use | Story 4.1 |
| Make docs crawlable and chunk-friendly | Story 1.2, Story 5.1, Story 5.2 |
| Add machine-readable trust signals | Story 4.2, Story 4.3, Story 5.2 |
| Keep Gait-like UI/UX colors and site feel | Story 1.3 |
| Optimize for agent answerability over human SEO | Story 2.2, Story 5.1, Story 6.1 |

## Test Matrix Wiring

Lane definitions:

- Fast lane: lint + focused docs contract checks + subset docs smoke.
- Core CI lane: full docs consistency + docs-site lint/build + docs smoke.
- Acceptance lane: deterministic end-to-end docs journey checks across key command pages and LLM surfaces.
- Cross-platform lane: docs parity/smoke checks on Linux/macOS/Windows where feasible.
- Risk lane: link integrity, nav/sitemap/robots contract checks, JSON-LD and LLM-surface checks.

Story-to-lane wiring:

| Story | Fast lane | Core CI lane | Acceptance lane | Cross-platform lane | Risk lane |
|---|---|---|---|---|---|
| 1.1 | Yes | Yes | No | Yes | No |
| 1.2 | Yes | Yes | No | Yes | Yes |
| 1.3 | No | Yes | No | No | No |
| 2.1 | Yes | Yes | Yes | Yes | No |
| 2.2 | Yes | Yes | Yes | Yes | Yes |
| 3.1 | Yes | Yes | Yes | Yes | Yes |
| 3.2 | Yes | Yes | Yes | Yes | Yes |
| 4.1 | Yes | Yes | Yes | Yes | Yes |
| 4.2 | Yes | Yes | Yes | Yes | Yes |
| 4.3 | Yes | Yes | Yes | Yes | Yes |
| 5.1 | Yes | Yes | Yes | Yes | Yes |
| 5.2 | Yes | Yes | Yes | Yes | Yes |
| 6.1 | Yes | Yes | Yes | Yes | Yes |
| 6.2 | Yes | Yes | Yes | Yes | Yes |
| 6.3 | No | Yes | Yes | No | Yes |

Gating rule:

- No docs-related PR merges to `main` unless all required lanes for touched stories pass.
- Release tags must include docs-site build and docs consistency gates.

## Epic 1: Docs-Site Foundation and Visual System

Objective: stand up a Gait-parity docs-site foundation for Wrkr with stable static export and consistent UI tokens.

### Story 1.1: Create Wrkr docs-site scaffold (Next.js static export)
Priority: P0
Tasks:
- Create `docs-site/` app scaffold mirroring Gait architecture:
  - app router, markdown ingestion, docs listing, docs detail routes.
- Configure static export, trailing slash, base path handling for GitHub Pages.
- Add docs-site package scripts (`dev`, `build`, `lint`, `start`) pinned to Node 22-compatible versions.
Repo paths:
- `docs-site/package.json`
- `docs-site/next.config.mjs`
- `docs-site/src/app/*`
- `docs-site/src/lib/*`
Run commands:
- `cd docs-site && npm ci`
- `cd docs-site && npm run lint`
- `cd docs-site && npm run build`
Test requirements:
- Docs-site builds with deterministic dependency lockfile.
- Route generation covers `docs/**`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: no, Cross-platform: yes, Risk: no.
Acceptance criteria:
- `docs-site/out` is generated successfully.
- Root, docs index, and doc detail routes render local markdown content.

### Story 1.2: Build docs navigation + docs home ladder
Priority: P0
Tasks:
- Add side navigation taxonomy for Wrkr docs and trust pages.
- Add docs home "tracks" for onboarding, risk workflows, proof/compliance, and machine-readable resources.
- Ensure stable URL conventions and lowercase slugs.
Repo paths:
- `docs-site/src/lib/navigation.ts`
- `docs-site/src/app/docs/page.tsx`
- `docs-site/src/app/docs/[...slug]/page.tsx`
Run commands:
- `cd docs-site && npm run build`
- `make test-docs-consistency`
Test requirements:
- Nav includes required routes.
- Docs home includes required routes.
- URL normalization and markdown link conversion are deterministic.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: no, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Required routes are discoverable from both side nav and docs home.
- Broken internal markdown links fail validation.

### Story 1.3: Apply Gait-like UI/UX visual tokens
Priority: P1
Tasks:
- Port the visual language direction from Gait:
  - dark gradient background, cyan/blue accent CTAs, dark card surfaces, clear code block theme.
- Ensure responsive layout parity:
  - desktop sidebar + mobile header drawer.
- Keep typography and spacing consistent for chunk readability.
Repo paths:
- `docs-site/src/app/globals.css`
- `docs-site/tailwind.config.ts`
- `docs-site/src/components/Header.tsx`
- `docs-site/src/components/Sidebar.tsx`
Run commands:
- `cd docs-site && npm run build`
Test requirements:
- Visual regressions checked with deterministic screenshots/manual QA checklist.
- Mobile and desktop navigation both function.
Matrix wiring:
- Fast: no, Core: yes, Acceptance: no, Cross-platform: no, Risk: no.
Acceptance criteria:
- Wrkr docs-site has the same design direction as Gait site without breaking readability.

## Epic 2: Narrative Canonicalization and Intent Architecture

Objective: create a clear, repeatable narrative and intent map that agents can quote precisely.

### Story 2.1: Canonical one-liner propagation
Priority: P0
Tasks:
- Insert canonical one-liner in key surfaces:
  - `README.md`, docs quickstart, docs-site homepage, `llms.txt`, `llm/product.md`.
- Add docs consistency check enforcing exact string match.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs-site/src/app/page.tsx`
- `docs-site/public/llms.txt`
- `docs-site/public/llm/product.md`
- `scripts/check_docs_consistency.sh` (new)
Run commands:
- `make test-docs-consistency`
Test requirements:
- Missing or altered one-liner fails with exit code `3`.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: no.
Acceptance criteria:
- One-liner is present and identical in all required surfaces.

### Story 2.2: Add high-intent page set for agent-quotable questions
Priority: P0
Tasks:
- Create one page per high-intent question:
  - scan org repos for agents/configs
  - detect headless agent risk
  - generate compliance evidence from scans
  - gate on drift/regressions.
- Use stable slugs under `/docs/intent/`.
- Include concise answer-first openings and short sections.
Repo paths:
- `docs/intent/scan-org-repos-for-ai-agents-configs.md`
- `docs/intent/detect-headless-agent-risk.md`
- `docs/intent/generate-compliance-evidence-from-scans.md`
- `docs/intent/gate-on-drift-and-regressions.md`
- `docs-site/src/lib/navigation.ts`
- `docs-site/src/app/docs/page.tsx`
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh`
Test requirements:
- Each intent page has frontmatter, deterministic headings, and explicit command anchor sections.
- Each intent page includes "When to use" and "When not to use".
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- All four intent pages are linked in nav and crawlable in generated sitemap.

## Epic 3: Command-First Verifiable Documentation Contract

Objective: ensure all answerable docs are reproducible and machine-verifiable.

### Story 3.1: Enforce page template for command-verifiable claims
Priority: P0
Tasks:
- Define required section contract for each high-intent page:
  - exact CLI commands
  - expected JSON keys
  - exit codes
  - sample output snippets
  - deterministic guarantees.
- Add script checks for section presence and required tokens.
Repo paths:
- `scripts/check_docs_consistency.sh`
- `docs/intent/*.md`
- `docs/commands/*.md` (where needed for parity links)
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh`
Test requirements:
- Missing command contract section fails docs consistency gate.
- Output snippets must match known key envelopes from docs smoke JSON artifacts.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Each high-intent page can be validated against CLI behavior without manual interpretation.

### Story 3.2: Strengthen docs smoke to cover new intent pages and outputs
Priority: P1
Tasks:
- Extend docs smoke script to validate JSON keys and error contracts referenced on intent pages.
- Ensure sample output snippets are sourced from deterministic smoke artifacts.
- Add fail-closed checks for stale/missing output examples.
Repo paths:
- `scripts/run_docs_smoke.sh`
- `scripts/check_docs_consistency.sh`
- `docs/intent/*.md`
Run commands:
- `scripts/run_docs_smoke.sh`
- `make test-docs-consistency`
Test requirements:
- Smoke validates `scan`, `evidence`, `verify`, `regress` command anchors and expected key fields.
- Mismatch between docs snippets and smoke output fails CI.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Docs remain synchronized with runtime command contracts.

## Epic 4: Deterministic Trust and Credibility Pages

Objective: publish machine-readable trust signals and credibility pages that improve agent reliability.

### Story 4.1: Add deterministic coverage/benchmark page and "when not to use"
Priority: P1
Tasks:
- Publish a matrix page:
  - what Wrkr detects
  - what it does not detect
  - why (static/offline/deterministic boundaries).
- Add explicit "when not to use Wrkr" constraints.
- Include deterministic benchmark framing and reproducibility notes.
Repo paths:
- `docs/trust/detection-coverage-matrix.md`
- `docs/trust/deterministic-guarantees.md`
- `docs-site/src/lib/navigation.ts`
Run commands:
- `make test-docs-consistency`
Test requirements:
- Required sections present and linked from nav/docs home.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Trust pages set clear boundaries and reduce over-claim risk.

### Story 4.2: Publish proof-chain, schema/contract, and versioned compatibility hub
Priority: P1
Tasks:
- Add concise pages for:
  - proof chain verification
  - schema/contract index
  - compatibility/version guarantees.
- Link to command references and schema paths.
Repo paths:
- `docs/trust/proof-chain-verification.md`
- `docs/trust/contracts-and-schemas.md`
- `docs/trust/compatibility-and-versioning.md`
- `docs-site/src/lib/navigation.ts`
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh --subset`
Test requirements:
- Pages include command anchors such as `wrkr verify --chain --json`.
- Schema paths and exit codes are validated against repository truth.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Agent can quote trust surfaces with direct, verifiable command and schema references.

### Story 4.3: Add security/privacy/release integrity trust pages
Priority: P1
Tasks:
- Add pages for:
  - security and privacy posture
  - release integrity (checksums, SBOM, provenance, signature verification).
- Include clear non-exfiltration and fail-closed statements.
Repo paths:
- `docs/trust/security-and-privacy.md`
- `docs/trust/release-integrity.md`
- `docs-site/src/lib/navigation.ts`
Run commands:
- `make test-docs-consistency`
Test requirements:
- Pages include concrete verification commands and expected outcomes.
- Required claims reference existing repo workflows and artifacts.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Machine-readable trust posture is easy to locate and operationally verifiable.

## Epic 5: Crawlability and Agent Discovery Surfaces

Objective: ensure docs are easy to crawl, chunk, and quote by assistants/search agents.

### Story 5.1: Add LLM context hub and resources
Priority: P0
Tasks:
- Add `/llms` page linking machine-readable resources.
- Create `llms.txt`, `llms-full.txt`, and `/llm/*.md` pages:
  - product
  - quickstart
  - security
  - contracts
  - faq.
- Ensure concise sections and stable URLs.
Repo paths:
- `docs-site/src/app/llms/page.tsx`
- `docs-site/public/llms.txt`
- `docs-site/public/llms-full.txt`
- `docs-site/public/llm/product.md`
- `docs-site/public/llm/quickstart.md`
- `docs-site/public/llm/security.md`
- `docs-site/public/llm/contracts.md`
- `docs-site/public/llm/faq.md`
Run commands:
- `cd docs-site && npm run build`
- `make test-docs-consistency`
Test requirements:
- `llms.txt` includes "When To Use" and "When Not To Use".
- Required command surface appears in `llms.txt`.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- LLM context resources are discoverable and consistent with docs command contracts.

### Story 5.2: Add sitemap, AI sitemap, robots, canonical metadata, and JSON-LD
Priority: P0
Tasks:
- Add `sitemap.xml`, `ai-sitemap.xml`, and `robots.txt` under docs-site public.
- Add canonical metadata and OpenGraph config in app layout.
- Add JSON-LD (`SoftwareApplication`, `FAQPage`) on homepage and FAQ-capable docs pages.
Repo paths:
- `docs-site/public/sitemap.xml`
- `docs-site/public/ai-sitemap.xml`
- `docs-site/public/robots.txt`
- `docs-site/src/app/layout.tsx`
- `docs-site/src/app/page.tsx`
- `docs-site/src/app/docs/[...slug]/page.tsx`
- `docs-site/src/lib/site.ts`
Run commands:
- `cd docs-site && npm run build`
- `make test-docs-consistency`
Test requirements:
- Required URLs exist in appropriate sitemap files.
- Robots references both sitemap files.
- FAQ extraction and JSON-LD rendering are deterministic.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Crawlability and machine-discovery resources pass automated checks.

## Epic 6: CI, Deployment, and Documentation Governance

Objective: make docs-site and answerability contracts first-class release gates.

### Story 6.1: Add docs consistency contract script for Wrkr docs-site
Priority: P0
Tasks:
- Create a Gait-style docs consistency script checking:
  - required files/routes
  - canonical one-liner placement
  - required intent pages
  - command token presence
  - exit code parity
  - nav/docs-home/sitemap/robots coherence
  - LLM surface required sections.
- Wire into `make test-docs-consistency`.
Repo paths:
- `scripts/check_docs_consistency.sh`
- `Makefile`
Run commands:
- `make test-docs-consistency`
Test requirements:
- Script exits non-zero on any drift.
- Error output pinpoints missing token/path/route.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Docs drift is blocked before merge.

### Story 6.2: Extend docs smoke and docs-site validation jobs
Priority: P1
Tasks:
- Add docs-site validation script for links/mermaid/readability parity.
- Expand docs smoke to include new intent and trust pages.
- Keep deterministic smoke artifacts for sample snippets.
Repo paths:
- `scripts/check_docs_site_validation.py`
- `scripts/run_docs_smoke.sh`
- `Makefile`
Run commands:
- `scripts/run_docs_smoke.sh`
- `python3 scripts/check_docs_site_validation.py --report wrkr-out/docs_site_validation_report.json`
Test requirements:
- Broken links, invalid mermaid, missing required sections fail.
- Smoke checks still validate command output contracts under `--json`.
Matrix wiring:
- Fast: yes, Core: yes, Acceptance: yes, Cross-platform: yes, Risk: yes.
Acceptance criteria:
- Docs-site quality checks produce deterministic pass/fail signals.

### Story 6.3: Add docs-site GitHub Pages workflow and CI integration
Priority: P0
Tasks:
- Add `docs.yml` workflow for Pages build/deploy on docs changes.
- Add docs-site lint/build and docs consistency checks in PR/main/release workflows.
- Upload docs-site validation artifacts for failed runs.
Repo paths:
- `.github/workflows/docs.yml`
- `.github/workflows/pr.yml`
- `.github/workflows/main.yml`
- `.github/workflows/release.yml`
Run commands:
- `gh workflow run docs.yml` (manual trigger optional)
- `make test-docs-consistency`
- `cd docs-site && npm run build`
Test requirements:
- PR lane runs docs checks on docs/code paths affecting docs truth.
- Main/release lanes enforce docs contracts.
Matrix wiring:
- Fast: no, Core: yes, Acceptance: yes, Cross-platform: no, Risk: yes.
Acceptance criteria:
- Wrkr docs-site deploys through CI and docs contracts are release-gated.

## Minimum-Now Sequence

1. Story 1.1
2. Story 1.2
3. Story 5.1
4. Story 5.2
5. Story 2.1
6. Story 2.2
7. Story 3.1
8. Story 6.1
9. Story 6.3
10. Story 3.2
11. Story 4.1
12. Story 4.2
13. Story 4.3
14. Story 6.2
15. Story 1.3

## Explicit Non-Goals

- No runtime scanner or risk engine behavior changes in this plan.
- No new hosted dashboard or telemetry product surface.
- No weakening of deterministic or fail-closed contracts for documentation convenience.
- No speculative benchmark claims without reproducible command/process anchors.
- No migration away from existing docs command contract coverage; this plan extends it.

## Definition of Done

- All P0 stories completed with required lanes green.
- Docs-site is deployed and publicly crawlable with stable routes.
- One-liner consistency check passes across all canonical surfaces.
- High-intent pages provide reproducible, command-verifiable guidance.
- LLM surfaces and trust pages are present, linked, and contract-validated.
- Docs checks are integrated into PR/main/release workflows and block on failure.
