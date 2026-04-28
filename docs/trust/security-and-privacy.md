---
title: "Security and Privacy Posture"
description: "Wrkr fail-closed safety, local-data handling defaults, and privacy boundaries for scan/evidence workflows."
---

# Security and Privacy Posture

## Security model

- Fail-closed behavior for unsafe operations.
- Deterministic policy/profile posture evaluation.
- Proof-chain verification for evidence integrity.

## Privacy model

- Scan data remains local by default.
- Secret values are not extracted; only risk context is emitted.
- Local path scans stay bounded to the selected repo root. Root-escaping symlinked skill, prompt, Cursor rule, dependency, config, env, workflow, identity, and MCP files are rejected with explicit deterministic diagnostics instead of being read.
- Hosted `--repo` and `--org` scans fetch only required detector files from GitHub into a local managed workspace under the selected scan state directory. Wrkr does not upload hosted source code.
- Hosted materialized source is ephemeral by default. After scan artifacts commit, Wrkr removes the managed materialized source root and records the result in `source_privacy.cleanup_status`.
- Shareable scan, report, SARIF, and evidence outputs serialize hosted repositories as logical locations such as `github://org/repo`; the private detector filesystem root is not serialized.
- Default shareable artifacts set `source_privacy.raw_source_in_artifacts=false`.
- `--source-retention retain_for_resume`, `--source-retention retain`, `--mode deep`, and `--allow-source-materialization` are explicit operator opt-ins that can leave more private repository content on disk or fetch generic source files for deeper static coverage.

## Command anchors

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr evidence --frameworks soc2 --output ./.tmp/evidence --json
wrkr verify --chain --json
```

## Q&A

### Does Wrkr collect or emit raw secret values?

No. Wrkr flags secret-risk context but does not extract and emit raw secret material.

### Can Wrkr run fully local for private repositories?

Yes. Default scan and evidence workflows operate locally with file-based artifacts and no required data exfiltration path.

### Does Wrkr retain private source code from hosted scans?

Not by default. Hosted scans use a local managed materialized workspace while detectors run, then clean it up after artifacts commit. Retention requires explicit `--source-retention retain_for_resume` or `--source-retention retain`.

### How does Wrkr handle symlinked files that point outside the selected repo root?

Wrkr fails closed at the detector file boundary. Escaping symlinked skill, prompt, Cursor rule, dependency, config, env, workflow, identity, and MCP files surface deterministic parse diagnostics (`parse_error.kind=unsafe_path`) and their outside-root content is not ingested.

### How does Wrkr prevent unsafe evidence operations?

Wrkr uses fail-closed checks and returns exit code `8` when an unsafe operation is blocked.
