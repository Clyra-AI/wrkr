---
title: "Built-in Policy Rules"
description: "Deterministic built-in Wrkr policy rules and governance intent, including prompt-channel controls."
---

# Built-in Policy Rules

Wrkr ships with a deterministic built-in rule pack at `core/policy/rules/builtin.yaml`. These rules are always loaded unless explicitly overridden by policy-file workflows.

## Rule pack goals

- Preserve deterministic policy outcomes for scan/report/score automation.
- Encode high-signal governance checks for discovery, risk, and lifecycle posture.
- Keep remediation intent explicit and machine-consumable.

## WRKR-016 prompt-channel governance rule

- Rule ID: `WRKR-016`
- Title: `Prompt-channel override and poisoning findings must be remediated`
- Severity: `high`
- Kind: `prompt_channel_governance`
- Remediation intent: remove prompt override/injection patterns, or gate residual risk behind explicit review and policy controls.

`WRKR-016` is the built-in governance anchor for prompt-channel findings and is designed to prevent silent acceptance of instruction-override or context-poisoning patterns.

## Command anchors

```bash
wrkr scan --path ./scenarios/wrkr/prompt-channel-poisoning/repos --profile strict --json
wrkr report --top 5 --json
wrkr score --json
```

## Overlay compatibility

- Use `--policy <path>` for organization-specific overlays.
- Keep built-in rule IDs stable in automations; treat ID changes as contract changes.
- Overlay rules should refine governance without weakening fail-closed behavior for high-risk ambiguity.
