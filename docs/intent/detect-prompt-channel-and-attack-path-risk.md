---
title: "How to detect prompt-channel and attack-path risk"
description: "Run an OWASP-focused deterministic workflow for prompt-channel poisoning signals and composed attack-path exposure."
---

# How to detect prompt-channel and attack-path risk

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## When to use

Use this when you need deterministic visibility into prompt-channel override/poisoning findings and how those findings compose into top attack paths.

## Exact commands

```bash
wrkr scan --path ./scenarios/wrkr/prompt-channel-poisoning/repos --production-targets ./docs/examples/production-targets.v1.yaml --json
wrkr report --top 5 --json
wrkr score --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

Optional enrich overlay (non-deterministic network metadata):

```bash
wrkr scan --path ./scenarios/wrkr/prompt-channel-poisoning/repos --enrich --github-api https://api.github.com --json
```

## Expected JSON keys

- `scan`: `findings`, `ranked_findings`, `top_findings`, `attack_paths`, `top_attack_paths`, `profile`, `posture_score`
- prompt-channel evidence fields: `pattern_family`, `evidence_snippet_hash`, `location_class`, `confidence_class`
- optional enrich fields (`--enrich`): `source`, `as_of`, `advisory_count`, `registry_status`, `enrich_quality`, `advisory_schema`, `registry_schema`, `enrich_errors`
- `report`: `top_findings`, `attack_paths`, `top_attack_paths`, `summary`
- `score`: `score`, `grade`, `breakdown`, `weighted_breakdown`, `weights`, `trend_delta` (optional: `attack_paths`, `top_attack_paths`)
- `regress run`: `status`, `drift_detected`, `reason_count`, `reasons` with `critical_attack_path_drift` summary details when thresholds are exceeded

## Exit codes

- `0`: success
- `3`: policy/schema violation
- `5`: regression drift detected
- `7`: dependency missing (for enrich/repo/org modes without required network source)

## Sample output snippet

```json
{
  "status": "ok",
  "top_findings": [
    {
      "id": "WRKR-016",
      "risk_score": 9.3,
      "title": "prompt-channel override and poisoning findings require remediation"
    }
  ],
  "top_attack_paths": [
    {
      "path_id": "acme/repo:prompt-channel->ci-headless->prod-write",
      "path_score": 9.6
    }
  ]
}
```

## Deterministic guarantees

- Prompt-channel matching and ranking use deterministic rules and stable tie-breakers.
- Attack-path scoring and top-N selection are deterministic for identical input state.
- `regress run` emits stable reason codes and summarized `critical_attack_path_drift` details.
- Offline default behavior is unchanged; enrich is optional and explicitly modeled with quality metadata.

## When not to use

- Do not use this flow as runtime exploit confirmation.
- Do not treat enrich metadata freshness as a substitute for local deterministic findings.
- Do not use this as a replacement for runtime enforcement controls.
