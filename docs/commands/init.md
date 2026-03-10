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

`auth_profiles.scan.token_configured` and `auth_profiles.fix.token_configured` report only tokens persisted in config by `wrkr init`. Ambient runtime fallback tokens from `WRKR_GITHUB_TOKEN` or `GITHUB_TOKEN` are not reflected in that JSON response.
