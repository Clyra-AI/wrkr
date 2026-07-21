# Composed Action Path Fixtures

This fixture pack is the canonical Wrkr-side contract surface for composed action paths and report-only proposed Action Contracts.

The expected fixture keeps composition, proposed contract, Agent Action BOM primary-view, decision-trace, evidence, and regress snapshot refs together so downstream products can validate joins without parsing report prose or relying on volatile `path_id` values alone.

All paths are repo-relative, payload-free, and safe for customer-redacted fixture use.

`expected/multi-stage-composition-fixtures.json` drives the real composition engine through bounded three-, four-, and five-stage repo/CI/cloud/SaaS/communications routes. It also pins cross-repo correlation and possible-versus-observed behavior without expanding the default report surface.
