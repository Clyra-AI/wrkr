# wrkr report

## Synopsis

```bash
wrkr report [--json] [--explain] [--md] [--md-path <path>] [--pdf] [--pdf-path <path>] [--template exec|operator|audit|public] [--share-profile internal|public] [--baseline <path>] [--previous-state <path>] [--top <n>] [--state <path>]
```

## Flags

- `--json`
- `--explain`
- `--md`
- `--md-path`
- `--pdf`
- `--pdf-path`
- `--template`
- `--share-profile`
- `--baseline`
- `--previous-state`
- `--top`
- `--state`

## Example

```bash
wrkr report --md --md-path ./.tmp/wrkr-summary.md --template operator --share-profile internal --json
wrkr report --pdf --pdf-path ./.tmp/wrkr-summary.pdf --template exec --json
wrkr report --md --md-path ./.tmp/wrkr-summary-public.md --template public --share-profile public --json
```

Expected JSON keys: `status`, `generated_at`, `top_findings`, `total_tools`, `tool_type_breakdown`, `compliance_gap_count`, `summary`, `md_path`, `pdf_path`.
