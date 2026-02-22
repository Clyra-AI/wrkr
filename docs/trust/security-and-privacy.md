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

### How does Wrkr prevent unsafe evidence operations?

Wrkr uses fail-closed checks and returns exit code `8` when an unsafe operation is blocked.
