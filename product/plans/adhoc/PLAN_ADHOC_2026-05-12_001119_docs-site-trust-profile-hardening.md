# Adhoc Plan: Docs Site Trust And Profile Hardening

Date: 2026-05-12
Profile: `wrkr`
Slug: `docs-site-trust-profile-hardening`
Recommendation source: user-provided unified code-review and app-audit findings covering docs-site Markdown rendering safety, production dependency audit handling for a moderate PostCSS advisory surfaced through Next, and stale Factory profile high-risk MCP surface mapping.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, docs-site, Factory profile, CI, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control loop. This plan must not implement Gait enforcement, Axym product logic, runtime interception, scan-time LLM behavior, or default telemetry.
- Core scan, risk, proof, evidence, regress, and verify behavior remains offline-first, file-based, zero-egress by default, and deterministic for the same input except explicit timestamp/version fields.
- Docs-site hardening is scoped to the documentation/UI surface. It must not introduce Node or browser dependencies into core Go runtime logic.
- Public docs rendering must treat Markdown as untrusted input even when the current source set is repo-owned. Future OSS PRs and generated docs content must not be able to publish raw script, unsafe attributes, unsafe URL schemes, or unescaped interpolated HTML through the static docs site.
- Dependency audit policy must stay pinned, explicit, and reproducible. Do not use forced dependency downgrades or floating upgrades to clear advisories.
- Moderate production dependency advisories on a public docs surface are not equivalent to core scanner proof-chain risk, but they must be tracked, bounded, and visible in release trust posture.
- Factory profile high-risk surfaces are review and automation contracts. They must point to current repo paths or explicit glob/pattern semantics, not stale directories.
- Lightweight plan validation is sufficient for this plan-only PR. Implementation PRs must run the focused docs-site and profile validation lanes named below.
- Changelog updates are required for implementation stories because the work changes public docs-site security posture, governance checks, and OSS trust/release guidance.

## Current Baseline (Observed)

- `docs-site/src/lib/markdown.ts` calls `marked.parse(...)` and customizes link, code, codespan, and heading rendering.
- `docs-site/src/components/MarkdownRenderer.tsx` renders the returned HTML through `dangerouslySetInnerHTML`.
- The custom Markdown link renderer interpolates mapped `href`, optional `title`, and rendered link text into HTML strings.
- A repository-wide search found no current Markdown docs containing obvious `<script`, event-handler attributes, iframe/style tags, or `javascript:` links, so the rendering risk is latent rather than currently exploited.
- `make docs-site-lint docs-site-build docs-site-check` passed during the audit. The production build emitted a Next/Turbopack NFT warning tied to dynamic filesystem reads in the docs loader, but completed successfully and generated 98 static pages.
- `make docs-site-audit-prod` runs `npm audit --omit=dev --audit-level=high`.
- `npm audit --omit=dev` reported two moderate production advisories for PostCSS XSS through Next's nested dependency. `docs-site/package-lock.json` currently resolves `next@16.2.6`, which depends on nested `postcss@8.4.31`; direct dev dependency `postcss` is `8.5.10`.
- During audit, npm's `next` `latest` dist-tag resolved to `16.2.6`, so there was no newer stable Next version available to clear the nested advisory without a forced breaking/downgrade path.
- `.github/workflows/pr.yml`, `.github/workflows/main.yml`, and `.github/workflows/docs.yml` run the same high-threshold docs-site production audit gate for docs-site or docs changes.
- `factory/profiles/wrkr.yaml` lists `core/mcp` under `code_review.high_risk_surfaces`, but `core/mcp` does not exist. MCP code lives under `core/detect/mcp` and adjacent detector packages.
- Core CLI/runtime audit was green: source acquisition, detection parsing, identity/lifecycle, risk, proof emission, evidence publishing, exit-code behavior, and CI/release gates had no P0/P1 findings.
- Validation observed during the unified audit: `make lint-fast`, `make test-fast`, `make build`, `make test-docs-consistency`, and `make docs-site-lint docs-site-build docs-site-check` passed.
- Scenario anchor evidence from the audit: scan completed with 20 tools, 134 findings, 44 control backlog items, ephemeral source retention, no raw source retained; evidence completed for `eu-ai-act,soc2`; verify completed with 306 proof records and an intact authenticated chain; regress init/run completed with no drift.

## Exit Criteria

- Docs-site Markdown rendering rejects or sanitizes raw HTML, unsafe attributes, unsafe URL schemes, and unsafe custom renderer interpolation while preserving expected docs links, code blocks, headings, Mermaid blocks, syntax highlighting, and static export behavior.
- Malicious Markdown fixtures prove that scripts, event handlers, `javascript:` links, malicious titles, and unsafe inline HTML do not reach rendered output.
- Docs-site production dependency advisory handling is explicit: moderate production advisories either fail the docs-site audit gate or require a checked-in, owner-scoped, expiring exception with documented rationale and upgrade trigger.
- The known Next/PostCSS moderate advisory has a tracked exception or patched upgrade path that avoids `npm audit fix --force` downgrade behavior.
- GitHub docs-site workflows and Makefile gates agree on audit threshold and exception behavior.
- Factory profile high-risk surfaces point at current Wrkr paths, including MCP detector packages, and a lightweight validation prevents future stale surface drift.
- Docs and changelog explain the docs-site trust posture, advisory policy, and profile validation behavior without implying any change to Wrkr core scan/proof guarantees.
- Implementation PRs include exact command evidence for docs-site lint/build/check/audit, profile validation, docs consistency, and the relevant fast lane.

## Public API and Contract Map

- CLI contracts:
  - No changes to `wrkr scan`, `wrkr report`, `wrkr evidence`, `wrkr verify`, `wrkr regress`, JSON contracts, proof records, or exit codes are planned.
  - Existing exit-code API remains unchanged: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, `8` unsafe operation blocked.
- Docs-site contracts:
  - Static docs routes, slug mapping, Markdown link conversion, code block rendering, Mermaid rendering, and docs-site smoke tests remain supported.
  - Raw or unsafe Markdown HTML is not a supported public contract.
  - Any new sanitizer or renderer configuration must be deterministic under `npm ci` and static export.
- CI/governance contracts:
  - `make docs-site-audit-prod` remains the local entry point for production docs-site dependency auditing.
  - If moderate advisories become blocking, workflows must call the same Makefile target rather than duplicating shell-only policy.
  - Advisory exceptions, if introduced, must be pinned to package/advisory/version/scope/owner/expiry and fail closed when expired or mismatched.
- Factory profile contracts:
  - `factory/profiles/wrkr.yaml` remains the source for profile-driven high-risk review surfaces.
  - High-risk surface validation may permit explicit missing-path exceptions only when the profile marks them as virtual, generated, or future-looking; ordinary repo paths must exist.
- Changelog contracts:
  - Implementation PRs must update `CHANGELOG.md` under `Security` or `Fixed`/`Changed` as story fields require.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/trust/release-integrity.md`
  - `docs/trust/deterministic-guarantees.md`
  - `docs-site/README.md`
  - `CHANGELOG.md`
- CI and governance docs impacted:
  - `.github/workflows/pr.yml`
  - `.github/workflows/main.yml`
  - `.github/workflows/docs.yml`
  - `Makefile`
  - `factory/profiles/wrkr.yaml`
  - Factory validation script or test docs, if added
- OSS trust baseline:
  - No generated docs-site output, local scan output, audit reports, proof bundles, binaries, or transient state should be committed.
  - Sanitizer tests must use synthetic malicious Markdown fixtures only.
  - Advisory exceptions must not hide or downgrade core scanner vulnerabilities; docs-site policy is scoped to production docs-site dependencies.
  - Documentation must distinguish docs-site security posture from Wrkr core scan/proof guarantees.

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| Docs-site Markdown can publish unsafe HTML/link content | P2 | Story 1.1 | Public docs rendering currently trusts repo Markdown too much for OSS contribution workflows. | Sanitize or disable unsafe HTML and escape custom renderer interpolation. | Public docs site cannot publish script/attribute/URL payloads from Markdown. |
| Add malicious Markdown fixture coverage | P2 | Story 1.1 | The current docs smoke tests prove happy paths, not hostile content. | Add focused unit/smoke tests for unsafe HTML, URLs, titles, code, and Mermaid preservation. | Regression protection for docs trust hardening. |
| Docs-site production audit passes with known moderate advisory | P2 | Story 1.2 | The high-only audit gate allows moderate production XSS advisories on a public web surface. | Add explicit moderate advisory policy or owner-scoped expiring exception until upstream patch is available. | Release trust posture is visible and reproducible. |
| Avoid forced downgrade or floating dependency fix | P2 | Story 1.2 | `npm audit fix --force` proposed a breaking downgrade path during audit. | Keep `npm ci`, lockfile, and exact exception/upgrade workflow. | Dependency handling remains boring, pinned, and auditable. |
| Factory profile references stale `core/mcp` path | P3 | Story 2.1 | Profile-driven reviews can under-focus MCP if high-risk surfaces are stale. | Update MCP surface paths and validate profile path existence. | Future code-review/app-audit runs use current architecture mapping. |
| Add docs and changelog for trust/profile policy | P2/P3 | Story 2.2 | Governance/security changes should be externally legible. | Update trust docs, docs-site README, and changelog entries. | Operators and contributors understand what changed and why. |

## Test Matrix Wiring

- Fast lane:
  - `cd docs-site && npm test -- --test-name-pattern <markdown-security>` if the implementation adds focused Node tests, or the equivalent repository test command selected by the implementer.
  - `make docs-site-lint`
  - `make docs-site-build`
  - `make docs-site-check`
  - `make docs-site-audit-prod`
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts` only if implementation touches shared contract, workflow, or governance checks that are enforced there.
- Acceptance lane:
  - `make test-docs-consistency`
  - `make test-focused-docs` when user-facing docs or docs-site examples change.
  - Scenario and acceptance lanes are not required unless implementation changes Wrkr CLI/runtime, report/evidence artifacts, or documented first-value command behavior.
- Cross-platform lane:
  - Docs-site static export and profile validation must avoid POSIX-only path assumptions.
  - Any new profile validator must normalize path separators and be covered by tests that do not depend on local absolute checkout paths.
- Profile/governance lane:
  - `python3 factory/scripts/validate_plan.py --repo-root . --plan-path <plan_path> --json` for this generated plan.
  - Add and run a focused Factory/profile validation command for high-risk surface existence, for example `python3 factory/scripts/validate_profiles.py --repo-root . --profile wrkr --json`, if that script is introduced.
  - `make lint-fast` must continue to pass if profile validation is wired into existing hygiene.
- Risk lane:
  - `make test-hardening` if sanitizer failure behavior, advisory exceptions, or profile validation fail-closed semantics are wired into hardening tests.
  - `make test-chaos` is not required unless implementation adds new filesystem, external dependency, concurrency, or retry behavior.
- Release/UAT lane:
  - Release workflow changes must be checked with the narrow equivalent of the docs-site production gates and branch-protection contract checks.

## Minimum-Now Sequence

- Wave 1 - Docs-site public trust hardening:
  - Story 1.1 sanitizes or safely renders Markdown and adds hostile fixture coverage.
  - Story 1.2 makes production dependency advisory handling explicit and reproducible.
- Wave 2 - Profile and governance hygiene:
  - Story 2.1 fixes the Wrkr profile MCP high-risk surface and adds stale-surface validation.
  - Story 2.2 updates docs, changelog, and contributor trust guidance for the new security posture.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No core Wrkr scan, risk, proof, evidence, verify, regress, lifecycle, or identity behavior changes.
- No Axym or Gait product functionality.
- No scan-time LLM calls, live endpoint probing, default telemetry, or scan-data exfiltration.
- No unpinned `@latest`, forced `npm audit fix --force`, or dependency downgrade solely to satisfy advisory output.
- No committing generated docs-site `out/`, `.next/`, `node_modules/`, audit reports, proof artifacts, local `.wrkr`, or `.tmp` state.
- No branch-protection, CI, proof verification, schema validation, or exit-code bypass.

## Definition of Done

- Every implementation story starts with failing tests or validation fixtures that encode the intended behavior.
- Docs-site Markdown security tests prove unsafe HTML, unsafe attributes, unsafe link schemes, malicious title/text interpolation, and raw HTML payloads are blocked or safely escaped.
- Safe docs features remain intact: repo-relative `.md` link conversion, external links with `rel="noopener noreferrer"`, code blocks, inline code, headings, Mermaid blocks with strict mode, syntax highlighting, static export, and docs validation.
- Docs-site dependency advisory policy is deterministic, owner-scoped, and enforced consistently through Makefile and workflows.
- Known moderate production advisories are either fixed through pinned dependency upgrades or covered by checked-in expiring exceptions with clear removal criteria.
- Factory profile high-risk surfaces match current repository layout or carry explicit future/virtual semantics.
- Validation commands and results are recorded in implementation PRs.
- Changelog entries ship with implementation PRs for security/governance-visible changes.

## Stories

### Story 1.1: Harden Docs-Site Markdown Rendering

Priority: P1

Tasks:

- Add failing tests that render malicious Markdown through the docs-site Markdown pipeline and assert unsafe output is not present.
- Cover at least: raw `<script>`, inline event handlers, unsafe `<style>` or raw HTML where applicable, `javascript:`/`data:` URL schemes, malicious `title` attributes, malicious link text, unsafe heading text, inline code escaping, fenced code escaping, and Mermaid block preservation.
- Choose the smallest deterministic rendering hardening path:
  - Prefer disabling raw HTML in `marked` plus safe custom renderer escaping when enough for current docs.
  - Otherwise add a pinned sanitizer dependency and configure an explicit allowlist for headings, paragraphs, lists, tables, links, code/pre, and Mermaid containers.
- Escape custom link renderer attributes and text before interpolation.
- Reject or neutralize unsafe URL schemes after `convertMarkdownHref(...)`.
- Preserve external link behavior with `target="_blank"` and `rel="noopener noreferrer"`.
- Preserve repo-relative `.md` link conversion for README, SECURITY, CONTRIBUTING, and docs tree links.
- Preserve strict Mermaid rendering and syntax highlighting behavior in `docs-site/src/components/MarkdownRenderer.tsx`.
- Add docs-site smoke coverage for one safe internal link, one safe external link, one code block, one Mermaid block, and one malicious fixture.
- Update docs-site validation if it currently assumes raw HTML is allowed.

Repo paths:

- `docs-site/src/lib/markdown.ts`
- `docs-site/src/components/MarkdownRenderer.tsx`
- `docs-site/src/lib/*.test.ts` or an adjacent test file selected by the implementer
- `docs-site/package.json`
- `docs-site/package-lock.json`
- `scripts/check_docs_site_validation.py` only if validation needs sanitizer-aware updates

Run commands:

- `cd docs-site && npm test -- --test-name-pattern markdown` or the focused test command added by the implementation
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `make docs-site-audit-prod`

Test requirements:

- Unit tests must assert hostile Markdown payloads do not appear as executable HTML or unsafe attributes.
- Snapshot/golden tests, if added, must be byte-stable under `npm ci`.
- Static build must generate docs pages successfully.
- Smoke tests must prove safe Markdown features are not broken.

Matrix wiring:

- Fast lane: docs-site focused Markdown security tests plus `make docs-site-lint`, `make docs-site-build`, `make docs-site-check`, and `make docs-site-audit-prod`.
- Core CI lane: `make lint-fast` only if shared Makefile/workflow policy is touched by this story.
- Acceptance lane: docs-site validation must cover at least one sanitized page and preserve link/code/Mermaid behavior.
- Cross-platform lane: renderer tests must avoid local absolute paths and OS-specific path separators.
- Risk lane: `make test-hardening` if sanitizer failure mode is wired into repository hardening tests.
- Gating rule: this story must land before public docs-site advisory policy is considered sufficient for launch trust.

Acceptance criteria:

- Unsafe raw HTML, event handlers, and unsafe URL schemes cannot reach rendered docs-site HTML.
- Existing docs-site pages still build and smoke-test successfully.
- The sanitizer or escaping behavior is deterministic and pinned.
- No core Go runtime dependency or scan behavior changes are introduced.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Hardened docs-site Markdown rendering so unsafe HTML, unsafe attributes, and unsafe link schemes are blocked or escaped while preserving deterministic static docs output.
Semver marker override: [semver:patch]
Contract/API impact: No Wrkr CLI/API impact; docs-site rendering contract tightens by dropping support for unsafe raw Markdown HTML.
Versioning/migration impact: Patch-level security hardening; any docs relying on raw HTML must be converted to supported Markdown/allowed elements.
Architecture constraints: Keep Node/TypeScript dependencies scoped to `docs-site`; preserve deterministic static export; do not touch Source, Detection, Risk, Proof emission, or Compliance/evidence boundaries.
ADR required: no
TDD first failing test(s): Malicious Markdown rendering test proving script/event/link payloads currently survive or are not explicitly blocked.
Cost/perf impact: low
Chaos/failure hypothesis: If sanitizer configuration is too strict or too loose, build/smoke tests either fail safe or malicious fixture assertions fail; no partial publish should be accepted.

### Story 1.2: Make Docs-Site Production Advisory Policy Explicit

Priority: P1

Tasks:

- Add failing policy coverage that proves production docs-site moderate advisories cannot silently pass without either a patched dependency state or a checked-in exception.
- Decide the enforcement model:
  - Option A: change `make docs-site-audit-prod` and workflows to fail on moderate production advisories.
  - Option B: keep the high threshold but add a strict exception file for named moderate production advisories with package, advisory ID, affected transitive path, current version, owner, rationale, expiry, and upgrade trigger.
- For the current Next/PostCSS advisory, add an exception only if no patched stable Next version is available at implementation time.
- Ensure exception validation fails closed when the advisory disappears, package path changes, expiry passes, owner/rationale is missing, or the lockfile version no longer matches.
- Avoid `npm audit fix --force` downgrade paths and avoid floating dependency upgrades.
- Keep `npm ci` and `package-lock.json` as the docs-site install contract.
- Update `.github/workflows/pr.yml`, `.github/workflows/main.yml`, and `.github/workflows/docs.yml` only through Makefile target alignment or minimal workflow wiring.
- Document how to remove the exception after upstream Next ships a patched nested PostCSS.

Repo paths:

- `Makefile`
- `docs-site/package.json`
- `docs-site/package-lock.json`
- `docs-site/security-advisory-exceptions.json` or equivalent checked-in policy file if Option B is selected
- `scripts/` for an advisory exception validator if introduced
- `.github/workflows/pr.yml`
- `.github/workflows/main.yml`
- `.github/workflows/docs.yml`
- `docs/trust/release-integrity.md`

Run commands:

- `make docs-site-audit-prod`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `make test-docs-consistency`
- `make lint-fast` if workflow/Makefile policy checks are touched

Test requirements:

- Add deterministic tests or script fixtures for allowed exception, expired exception, mismatched package/version, missing owner/rationale, and advisory no longer present.
- If the audit threshold changes to moderate, prove docs-site audit fails on moderate production advisories without an exception.
- If an exception file is used, prove the current known advisory is the only accepted exception.

Matrix wiring:

- Fast lane: advisory policy tests plus `make docs-site-audit-prod`.
- Core CI lane: `make lint-fast` if Makefile/workflow governance checks are touched.
- Acceptance lane: docs consistency must mention the production advisory policy when docs change.
- Cross-platform lane: advisory validator, if introduced, must parse lockfile and audit JSON without shell-specific behavior.
- Risk lane: `make test-hardening` if advisory exceptions become a fail-closed security policy path.
- Gating rule: no known moderate production docs-site advisory may remain unpatched and untracked after this story.

Acceptance criteria:

- Moderate production advisories on the public docs-site are no longer invisible in release trust posture.
- The current Next/PostCSS advisory is either fixed by a pinned upgrade or tracked by a strict expiring exception.
- Workflows and Makefile agree on the docs-site production audit contract.
- No forced downgrade or unpinned dependency update is introduced.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Added explicit docs-site production advisory governance so moderate production dependency advisories either fail the audit gate or require an owner-scoped expiring exception.
Semver marker override: [semver:patch]
Contract/API impact: No Wrkr CLI/API impact; CI/docs-site audit policy becomes stricter and more explicit.
Versioning/migration impact: Patch-level governance hardening; contributors may need to update or justify docs-site production dependency advisories before merge.
Architecture constraints: Keep dependency policy scoped to docs-site production dependencies and workflow/Makefile gates; no core scanner dependency changes.
ADR required: no
TDD first failing test(s): Advisory policy fixture proving a moderate production advisory passes today under high-only audit policy without explicit exception.
Cost/perf impact: low
Chaos/failure hypothesis: If npm advisory output changes shape or the registry is unavailable, the validator must fail closed with a clear CI error rather than silently approving an unknown advisory state.

### Story 2.1: Fix And Validate Profile High-Risk Surfaces

Priority: P2

Tasks:

- Replace stale `core/mcp` in `factory/profiles/wrkr.yaml` with current MCP detector paths, including `core/detect/mcp` and any adjacent current MCP gateway/WebMCP packages that should remain high-risk review surfaces.
- Add a lightweight profile validation script or extend an existing Factory validation script to check that profile high-risk surfaces resolve to existing repo paths unless explicitly marked virtual/future.
- Validate profile `standards`, `docs.user_facing_paths`, and `code_review.high_risk_surfaces` enough to catch missing files/directories without forcing full repo validation.
- Add tests or fixtures covering a valid profile, a missing high-risk surface, and an explicit virtual/future exception if that concept is supported.
- Wire the profile validation into the appropriate lightweight governance lane without making plan-only PRs run full repo validation.
- Keep the validator path-portable by using `$REPO_ROOT`/repo-relative paths, not developer-specific absolute paths.

Repo paths:

- `factory/profiles/wrkr.yaml`
- `factory/scripts/` for profile validation if introduced
- `factory/skills/code-review/SKILL.md` only if profile semantics need documentation
- `factory/skills/app-audit/SKILL.md` only if profile semantics need documentation
- `testinfra/hygiene` or Factory tests if profile validation is enforced from Go tests

Run commands:

- `python3 factory/scripts/validate_plan.py --repo-root . --plan-path product/plans/adhoc/<plan>.md --json`
- `python3 factory/scripts/validate_profiles.py --repo-root . --profile wrkr --json` if introduced
- `make lint-fast` if the validator is wired into repo hygiene

Test requirements:

- Validator must fail on a missing ordinary high-risk surface.
- Validator must pass on current Wrkr profile after MCP path correction.
- Tests must not require network access.
- Output must be machine-readable when `--json` is requested.

Matrix wiring:

- Fast lane: focused profile validation tests and the new profile validation command if introduced.
- Core CI lane: `make lint-fast` when profile validation is wired into repo hygiene.
- Acceptance lane: not required unless profile fields used by scenario or acceptance tooling change.
- Cross-platform lane: validation must use repo-relative path handling and normalize separators.
- Risk lane: `make test-hardening` only if stale profile surfaces become enforced fail-closed behavior in hardening.
- Gating rule: profile path correction should land before the next profile-driven code review or app audit.

Acceptance criteria:

- `wrkr` profile high-risk surfaces match current repository architecture.
- Future code-review and app-audit runs do not require manual correction for MCP surface coverage.
- Missing high-risk profile paths fail a lightweight validation lane before they drift into audit automation.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed Wrkr Factory profile high-risk MCP surface mapping and added lightweight validation so profile-driven reviews do not drift from the current repository layout.
Semver marker override: [semver:patch]
Contract/API impact: No Wrkr CLI/API impact; Factory/profile governance contract becomes stricter.
Versioning/migration impact: Patch-level governance fix; stale profile entries must be updated or explicitly marked as non-path surfaces.
Architecture constraints: Preserve architecture boundary naming from `product/architecture_guides.md`; validation must remain profile-driven and path-portable.
ADR required: no
TDD first failing test(s): Profile validation test showing current `core/mcp` is a missing high-risk surface.
Cost/perf impact: low
Chaos/failure hypothesis: If a profile points at a removed security-critical surface, validation fails before review automation produces a false sense of coverage.

### Story 2.2: Sync Docs And Changelog For Trust Hardening

Priority: P2

Tasks:

- Update `docs/trust/release-integrity.md` to explain docs-site production advisory treatment, exception requirements, and upgrade/removal workflow.
- Update `docs/trust/deterministic-guarantees.md` only if implementation changes any documented docs-site or governance guarantee.
- Update `docs-site/README.md` with the safe Markdown rendering contract and local validation commands.
- Update `README.md` only if the public first-value/trust summary needs a short note about docs-site public trust hardening.
- Add concise `CHANGELOG.md` entries under `Security` and `Fixed`/`Changed` matching the implementation stories.
- Ensure docs avoid overclaiming: docs-site hardening improves public documentation trust, not core proof-chain guarantees.
- Run docs consistency and docs-site gates after edits.

Repo paths:

- `docs/trust/release-integrity.md`
- `docs/trust/deterministic-guarantees.md`
- `docs-site/README.md`
- `README.md`
- `CHANGELOG.md`

Run commands:

- `make test-docs-consistency`
- `make test-focused-docs`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`

Test requirements:

- Docs consistency checks must pass.
- Docs-site validation must pass with the sanitized renderer and advisory policy.
- Changelog entries must use required sections and semver markers.

Matrix wiring:

- Fast lane: `make test-docs-consistency`, `make test-focused-docs`, and docs-site lint/build/check.
- Core CI lane: `make lint-fast` if changelog or docs policy checks are enforced there.
- Acceptance lane: not required unless user-facing command examples or first-value flows change.
- Cross-platform lane: docs examples must remain shell-portable or clearly scoped when platform-specific.
- Risk lane: not required unless docs introduce security policy validation behavior.
- Gating rule: this story closes the implementation wave only after docs and changelog match the shipped behavior.

Acceptance criteria:

- Operators and contributors can see how docs-site Markdown security and advisory exceptions are enforced.
- Changelog captures security/governance-visible changes.
- Docs keep Wrkr's static scan/proof boundary clear.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Updated docs-site and release-trust guidance for safe Markdown rendering, production dependency advisory handling, and profile high-risk surface validation.
Semver marker override: [semver:patch]
Contract/API impact: No Wrkr CLI/API impact; public docs/trust guidance changes.
Versioning/migration impact: Patch-level documentation and governance update.
Architecture constraints: Documentation must align with `product/dev_guides.md` and `product/architecture_guides.md`; no new product claims beyond observed behavior.
ADR required: no
TDD first failing test(s): Docs consistency or docs-site validation assertion added before prose update if a machine-checkable docs rule is introduced.
Cost/perf impact: low
Chaos/failure hypothesis: If docs drift from implemented gates, docs consistency or docs-site validation should fail before merge.
