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

The `/scan` route is a thin bootstrap shell only. It prepares an equivalent handoff, points back to existing Wrkr org scan contracts, and projects returned machine-readable summaries without introducing dashboard persistence.

## SEO and AEO Assets

- `public/robots.txt`
- `public/sitemap.xml`
- `public/ai-sitemap.xml`
- `public/llms.txt`
- `public/llm/*.md` assistant context pages
- JSON-LD on homepage (`SoftwareApplication`, `FAQPage`)
