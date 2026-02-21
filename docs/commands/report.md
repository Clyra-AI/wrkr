# wrkr report

## Synopsis

```bash
wrkr report [--json] [--explain] [--pdf] [--pdf-path <path>] [--top <n>] [--state <path>]
```

## Flags

- `--json`
- `--explain`
- `--pdf`
- `--pdf-path`
- `--top`
- `--state`

## Example

```bash
wrkr report --pdf --pdf-path ./.tmp/wrkr-report.pdf --json
```

Expected JSON keys: `status`, `generated_at`, `top_findings`, `total_tools`, `tool_type_breakdown`, `compliance_gap_count`, `pdf_path`.
