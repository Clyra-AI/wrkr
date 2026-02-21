# Security Policy

## Private Reporting

Do not open public issues for suspected vulnerabilities.

Report privately using GitHub Security Advisories:

- <https://github.com/Clyra-AI/wrkr/security/advisories/new>

If GitHub private advisories are unavailable, open a maintainers-only channel and include "SECURITY" in the title.

## What To Include

Please include:

- affected component/file/command and version/commit
- impact summary (confidentiality, integrity, availability)
- reproduction steps with deterministic inputs
- proof-of-concept or logs (scrub secrets)
- suggested mitigations/workarounds if known

## Response Expectations

- acknowledgment: within 3 business days
- triage/update: within 7 business days after acknowledgment
- remediation target:
- critical/high severity: target fix or mitigation within 30 days
- medium/low severity: target fix in a scheduled release cycle

Timelines may shift for complex supply-chain or coordinated multi-project issues; maintainers will communicate status updates in the advisory thread.

## Supported Fix Targets

Security fixes are prioritized for:

- `main`
- latest supported release line/tag maintained by the project

Older, unsupported lines may not receive backports.

## Disclosure Coordination

- keep details private until maintainers confirm a fix or mitigation is available
- coordinate publication timing with maintainers to protect downstream users
- when disclosed, include affected versions, fixed versions, and upgrade guidance
