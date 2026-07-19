# Action Contract Cross-Product Conformance

This pack is the authoritative Wrkr-produced Action Contract interoperability
fixture. It covers customer data to egress, workflow to deploy, secret to
network, package to release, excessive child authority, failed effect
validation, approval expiry, compensation, and supersession.

The generator performs a real scan of
`scenarios/wrkr/agent-action-bom-demo/after/repos`, creates scenario-specific
saved states from the production composition model, runs the production
`export action-contracts` command, and runs the production
`action-contract-packet` JSON and Markdown renderers. The committed artifact
bytes are never written by hand. The fixed lifecycle timestamp in scenario
inputs is deliberate evidence data; no wall-clock generator timestamp enters
the artifact or packet identity.

Check committed bytes without mutation:

```bash
scripts/generate_action_contract_conformance.sh --check
```

Review and explicitly update the goldens:

```bash
scripts/generate_action_contract_conformance.sh --update
git diff -- scenarios/cross-product/action-contract-interop/expected
```

`expected/fixture-manifest.json` pins the producer/schema versions, exact file
SHA-256 digests, canonical artifact digest, artifact/contract/family/revision
identity, and the Gait/Axym consumer entrypoints for every scenario. Tests
always regenerate to temporary storage; they never update committed files.

Tier 12 consumers are owned by Gait and Axym. Configure executable wrappers in
`WRKR_GAIT_ACTION_CONTRACT_CONSUMER` and
`WRKR_AXYM_ACTION_CONTRACT_CONSUMER`, then run:

```bash
scripts/test_action_contract_interop.sh
```

Each wrapper receives the exact committed artifact path as its sole argument
and must return a JSON receipt containing `consumer`, `version`, `scenario_id`,
`artifact_sha256`, and `status: pass`. Missing wrappers return
`dependency_missing` with exit `7`; Wrkr does not substitute a local consumer.
Successful versioned receipts are written under
`.tmp/action-contract-interop-receipts/` by default and are required by the
release interoperability gate. Each aggregate receipt pins fixture version
`1`, the exact fixture-manifest SHA-256, the producer and schema versions, the
external consumer version, and every scenario artifact digest.
