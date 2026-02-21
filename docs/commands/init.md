# wrkr init

## Synopsis

```bash
wrkr init [--non-interactive] (--repo <owner/repo> | --org <org> | --path <dir>) [--scan-token <token>] [--fix-token <token>] [--config <path>] [--json]
```

## Flags

- `--json`
- `--non-interactive`
- `--repo`
- `--org`
- `--path`
- `--scan-token`
- `--fix-token`
- `--config`

## Example

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
```

Expected JSON keys: `status`, `config_path`, `default_target`, `auth_profiles`.
