# Public-Surface Assessment Example

Use this pattern when you want a deterministic, opt-in public-evidence demo that
stays honest about what Wrkr can and cannot prove from public information alone.

## Exact commands

```bash
wrkr scan --target public-surface:./docs/examples/public-surface-assessment.v1.yaml --state ./.wrkr/last-scan.json --json
wrkr report --state ./.wrkr/last-scan.json --template public --md --md-path ./.tmp/public-surface.md --json
```

## Why this exists

- It supports outbound and demo workflows without requiring a private customer repo.
- It keeps public observed facts separate from inferred public context.
- It makes unsupported public claims and absent private evidence explicit instead
  of letting them drift into buyer-facing overclaims.

## Difference from a private scan

- Public-surface mode can describe only the public evidence supplied in the
  manifest plus clearly labeled inference rationale.
- It cannot verify private runtime behavior, approvals, credential authority,
  production controls, or managed-platform reachability without private
  evidence.
- The resulting report keeps those boundaries visible in JSON and Markdown.

## Safe input contract

- `public_ref` must be an `http` or `https` URL.
- `capture_path`, when present, must stay inside the manifest directory.
- Use only public or synthetic fixture material in these manifests.
