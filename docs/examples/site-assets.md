# Website-Ready Demo Assets

Use this page when you need deterministic, publish-safe Wrkr artifacts for the
website, outbound demos, docs screenshots, or analyst briefings.

## Exact command

```bash
go run ./scripts/generate_site_assets --repo-root . --output-dir ./docs/examples/site-assets
```

## Generated files

- `docs/examples/site-assets/sample-agent-action-bom.json`: customer-redacted BOM projection derived from the real multi-repo report path.
- `docs/examples/site-assets/sample-control-path-graph.json`: customer-redacted graph data for action/control visualizations.
- `docs/examples/site-assets/sample-redacted-report.md`: customer-redacted executive markdown report.
- `docs/examples/site-assets/interactive-lab-data.json`: compact website/lab data for rollups, governed-usage metrics, proof counts, and top sample paths.
- `docs/examples/site-assets/architecture-boundary.json`: source, detection, aggregation, and proof boundary page data.
- `docs/examples/site-assets/local-private-posture.md`: local/private posture explanation derived from evidence metadata.
- `docs/examples/site-assets/site-asset-manifest.json`: deterministic manifest with source scenario, commands, and SHA256 digests.

## Safety contract

- Assets come only from the fake fixture at `scenarios/wrkr/scan-mixed-org/repos`.
- Published outputs must stay free of raw owner handles, proof refs, graph refs,
  secret-like strings, and machine-local absolute paths.
- Do not hand-edit the generated files. The generator plus
  `go test ./internal/siteassets -count=1` are the drift gate.

## Why this exists

- It gives the docs site and website a real product surface instead of hand-made
  marketing JSON.
- It keeps website assets aligned with Wrkr's actual scan, report, and evidence
  pipeline.
- It preserves the default `local_only` posture while still making redacted,
  shareable examples available for public materials.
