# wrkr init

## Synopsis

```bash
wrkr init [--non-interactive] (--repo <owner/repo> | --org <org> | --path <dir>) [--github-api <url>] [--scan-token <token>] [--fix-token <token>] [--config <path>] [--json]
```

`wrkr init` still persists one default target in config in this wave.
Multi-target scans are driven explicitly at runtime through the `wrkr scan` target-set syntax rather than config defaults.

## Flags

- `--json`
- `--non-interactive`
- `--repo`
- `--org`
- `--path`
- `--github-api`
- `--scan-token`
- `--fix-token`
- `--config`

## Example

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr init --non-interactive --org acme --github-api https://api.github.com --json
```

Expected JSON keys: `status`, `config_path`, `default_target`, `auth_profiles`, additive `hosted_source`, additive `next_step`.

`auth_profiles.scan.token_configured` and `auth_profiles.fix.token_configured` report only tokens persisted in config by `wrkr init`. Ambient runtime fallback tokens from `WRKR_GITHUB_TOKEN` or `GITHUB_TOKEN` are not reflected in that JSON response.
`hosted_source.github_api_configured` and `hosted_source.github_api_base` report whether Wrkr persisted a hosted GitHub API base for repo/org scans. Ambient runtime fallback from `WRKR_GITHUB_API_BASE` is not reflected in that JSON response.
For repo/org defaults, `next_step` points at the config-backed `wrkr scan --config ... --json` flow. If no hosted GitHub API base was persisted, the guidance stays fail closed and tells you to set `--github-api`, persist `github_api_base` via `wrkr init`, or export `WRKR_GITHUB_API_BASE` before running the hosted scan.
