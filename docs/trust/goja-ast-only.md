# goja AST-Only Guardrails

Wrkr uses `github.com/dop251/goja` parser/AST packages for WebMCP JavaScript declaration parsing.

## Rationale

- JavaScript declaration surfaces are often embedded in repository files.
- AST parsing gives deterministic structural analysis without runtime side effects.
- Parser-based analysis improves resilience versus regex-only parsing while keeping fail-closed behavior.

## Guardrails

- Allowed usage: `goja/parser` and `goja/ast` for static parse/tree traversal only.
- Disallowed usage: runtime evaluation paths (`goja.New`, `RunString`, `RunProgram`, dynamic function execution).
- Detector behavior remains file-based and static; no live JS execution.

## Enforcement

- Unit test `TestWebMCPParserRejectsRuntimeEvalPath` blocks runtime-eval token regressions.
- Parse errors are surfaced as structured findings (`parse_error`) rather than silently skipped.
