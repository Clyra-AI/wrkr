# Wrkr Security and Privacy

- Developer-machine and org scans are deterministic saved-state inventory, not live endpoint probing.
- Fail-closed behavior for unsafe evidence output paths.
- Deterministic command outputs with stable exit codes.
- Static discovery mode by default, avoiding live probing.
- Local-first scan/evidence workflow by default.
- Secret-value extraction is out of scope; only risk context is emitted.
- Wrkr does not replace MCP/package vulnerability scanners such as Snyk.
- Gait is optional for control-layer trust overlays and enforcement.

Operational references:

- `/docs/trust/security-and-privacy/`
- `/docs/trust/deterministic-guarantees/`
- `/docs/trust/proof-chain-verification/`
- `/docs/examples/security-team/`
- `/docs/commands/root/`
