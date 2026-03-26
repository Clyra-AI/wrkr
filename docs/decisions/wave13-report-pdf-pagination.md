# ADR: Wave 13 Deterministic Wrapped and Paginated PDF Reports

Date: 2026-03-26
Status: accepted

## Context

Wrkr's original PDF renderer emitted one page and truncated long lines, which was deterministic but not sufficient for executive distribution. The launch plan required wrapped, paginated output without introducing network, font, or heavyweight rendering dependencies.

## Decision

1. Keep the renderer internal and pure Go.
2. Normalize markdown lines, wrap them deterministically to a fixed character width, and paginate them to a fixed line budget per page.
3. Preserve the existing `--pdf` and `pdf_path` contract while changing only the rendered bytes and page structure.
4. Back the board-ready claim with explicit executive report acceptance fixtures.

## Rationale

- Fixed wrapping/pagination rules preserve repeat-run determinism.
- Avoiding external font or browser renderers keeps the artifact offline-safe and auditable.
- Executive acceptance fixtures are required so report-quality claims remain evidence-backed rather than copy-led.

## Consequences

- Long executive summaries no longer silently fall off-page.
- PDF bytes change relative to the earlier single-page renderer, but the CLI contract does not.
- The board-ready claim is now blocked on acceptance fixtures instead of informal visual inspection.
