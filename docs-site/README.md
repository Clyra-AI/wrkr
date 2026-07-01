# Wrkr Docs Site

Static-first Next.js site for GitHub Pages deployment, with an optional server-capable mode for the thin `/scan` bootstrap shell.

## Local Development

```bash
cd docs-site
npm ci
npm run dev
```

## Deployment Modes

- Static default: `npm run build`
- Server-capable bootstrap shell: `WRKR_DOCS_DEPLOY_MODE=server npm run build`

Static mode keeps GitHub Pages compatibility. Server mode is reserved for a callback-capable deployment of the read-only `/scan` bootstrap flow and does not change Wrkr CLI contracts.

## Build

```bash
cd docs-site
npm run build
```

Output is written to `docs-site/out/`.

When `WRKR_DOCS_DEPLOY_MODE=server` is set, Next emits a runtime build instead of `out/`.

## Content Sources

- `docs/**`
- `README.md`
- `SECURITY.md`
- `CONTRIBUTING.md`

The site ingests markdown from the repository and renders static docs routes.

## Markdown Trust Contract

- Repository Markdown is treated as untrusted input on the public docs site.
- Raw HTML is escaped instead of rendered.
- Unsafe URL schemes such as `javascript:` and `data:` are neutralized before HTML output.
- Custom link, heading, inline code, and fenced code rendering escape interpolated values before they reach `dangerouslySetInnerHTML`.
- Supported safe features remain intact: repo-relative `.md` link conversion, external links with `target="_blank"` plus `rel="noopener noreferrer"`, code blocks, inline code, headings, and strict Mermaid rendering.

Docs that relied on raw HTML should be rewritten using supported Markdown instead of expecting passthrough HTML behavior.

## Validation

```bash
cd docs-site
npm test -- --test-name-pattern markdown
```

```bash
make docs-site-lint
make docs-site-build
make docs-site-check
make docs-site-audit-prod
```

`make docs-site-audit-prod` validates live `npm audit --omit=dev` output against [`docs-site/security-advisory-exceptions.json`](security-advisory-exceptions.json). Exceptions are owner-scoped, expiring, and pinned to the exact advisory, affected node path, direct dependency, and locked version so the gate fails closed when upstream fixes land or the lockfile drifts.

The audit validator also supports deterministic date injection for tests with `--today YYYY-MM-DD` and non-failing lead-time warnings with `--warn-expiring-within-days N`. The weekly `docs-site-audit-watch` workflow uses the warning mode to open or update a GitHub issue before an exception expires.

The `/scan` route is a thin bootstrap shell only. It prepares an equivalent handoff, points back to existing Wrkr org scan contracts, and projects returned machine-readable summaries without introducing dashboard persistence.

## SEO and AEO Assets

- `public/robots.txt`
- `public/sitemap.xml`
- `public/ai-sitemap.xml`
- `public/llms.txt`
- `public/llm/*.md` assistant context pages
- JSON-LD on homepage (`SoftwareApplication`, `FAQPage`)
