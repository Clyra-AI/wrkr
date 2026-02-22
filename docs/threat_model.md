---
title: "Threat Model"
description: "Threat model for Wrkr discovery boundaries, proof integrity, deterministic outputs, and privacy posture."
---

# Wrkr Threat Model

## Security Objectives

- Prevent silent drift in AI tooling posture.
- Preserve integrity of risk/evidence outputs.
- Fail closed on unsafe operations.
- Keep scan data local by default.

## Trust Boundaries

1. Source acquisition boundary (`repo`, `org`, `path`).
2. Detection and normalization boundary.
3. Proof chain and evidence output boundary.
4. CI gate consumer boundary.

## Threats and Controls

| Threat | Control |
|---|---|
| Synthetic or missing source data accepted silently | dependency-missing fail-closed (`7`) |
| Evidence path misuse | unsafe operation blocked (`8`) |
| Proof tampering | `wrkr verify --chain --json` |
| Schema drift impacting automation | command/schema contract tests |
| Secret leakage through findings | secret presence-only detection |

## Command Anchors

```bash
wrkr scan --org acme --github-api https://api.github.com --json
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
wrkr verify --chain --json
```

## Q&A

### What threat does exit code `8` mitigate?

Exit code `8` covers unsafe operations blocked by fail-closed controls, such as unsafe evidence output behavior.

### How do I verify evidence has not been tampered with?

Run `wrkr verify --chain --json` (or include `--state` when needed). Exit code `2` indicates chain verification failure.

### Does Wrkr transmit scan data outside the environment by default?

No. Wrkr keeps scan data local by default and focuses on file-based, auditable artifacts.
