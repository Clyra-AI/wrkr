---
title: "EU AI Act Preparation: What Your Auditor Will Ask (and What You Can't Answer Yet)"
description: "A short, blunt audit-readiness checklist for CISOs and GRC leaders. What auditors ask, what most teams can't answer today, and how to produce credible evidence fast with Wrkr."
---

If you assume you are within ~6 months of an EU AI Act enforcement milestone, treat this as an audit-readiness drill: can you produce evidence on demand, not intent.

This is not legal advice. The EU AI Act is phased and your obligations depend on your role (provider, deployer, importer, distributor) and the type of AI system. Use this as a practical checklist to close evidence gaps fast.

## What Your Auditor Will Ask

These are the questions that show up in real audits because they map to governance, control effectiveness, and repeatability.

### 1) Where Does AI Touch Your Business and SDLC?

Your auditor is not asking for a list of vendors. They want a bounded inventory with ownership.

You will be asked:
- "Which AI systems exist, who owns them, and where are they used (customer-facing, internal, engineering)?"
- "Which repos, workflows, and services depend on AI tooling?"
- "Which AI tools can change code, deployments, infrastructure, or data?"

What you probably cannot answer today:
- A complete, current inventory of agent tooling across repos and CI.
- A defensible list of "AI can touch production" pathways.

What Wrkr can do:
- Discover AI tooling declarations and execution contexts across repos (agents, skills, MCP declarations, CI patterns).
- Emit a deterministic inventory you can hand to an auditor and regenerate later.

## 2) What Is Your Risk Classification and Governance Posture?

Auditors will push for a crisp story:
- "Which systems are out of scope vs in scope, and why?"
- "Which are high-risk, and where is the technical documentation?"
- "What is your human oversight model and who can stop the system?"
- "How do you handle incidents and post-market monitoring?"

What Wrkr does and does not cover:
- Wrkr helps with the SDLC governance and evidence trail for AI development tooling (discovery, privilege, execution context, drift).
- Wrkr does not classify your AI system under the Act, document training data, or generate your Annex-style technical file.

## 3) Can You Prove Control Over Tooling That Can Change Production, Code, or Credentials?

This is where most teams fail audits: they can describe intent, but cannot prove enforcement.

You will be asked:
- "Show me which tools are write-capable."
- "Show me which tools have credential access."
- "Show me which tools can reach production targets."
- "Show me approvals, lifecycle states, and drift detection."
- "Show me evidence of this being true on date X."

What Wrkr can do quickly:
- Compute a privilege budget summary (how many tools are write-capable, credential-capable, exec-capable).
- Produce a per-agent privilege map for review and remediation prioritization.
- When configured, compute a production-write subset: write-capable tools that match your defined production targets.
- Emit proof artifacts that can be verified later (evidence chain and stable exit codes for CI gates).

## Answer It In 10 Minutes (Evidence Pack)

This is the minimum you want to be able to run live on a call with an auditor.

### Step 1: Generate an inventory and posture snapshot

Use the mode that matches where your repos live.

Local repos:
```bash
wrkr scan --path /path/to/repos --state ./.wrkr/state.json --json > ./.wrkr/scan.json
```

GitHub org:
```bash
wrkr scan --org YOUR_ORG --github-api https://api.github.com --state ./.wrkr/state.json --json > ./.wrkr/scan.json
```

### Step 2: Add a human-readable artifact for audit packets
```bash
wrkr scan --path /path/to/repos --state ./.wrkr/state.json --report-md --report-md-path ./.wrkr/scan-summary.md --json > /dev/null
```

### Step 3: Gate drift (prove you will detect regressions)

Initialize a baseline from a known-good scan:
```bash
wrkr regress init --baseline ./.wrkr/state.json --output ./.wrkr/regress-baseline.json --json > ./.wrkr/regress-init.json
```

Run drift detection (exit code 5 indicates regression drift):
```bash
wrkr regress run --baseline ./.wrkr/regress-baseline.json --state ./.wrkr/state.json --json > ./.wrkr/regress-run.json
```

### Step 4: Prove integrity of what you hand over
```bash
wrkr verify --chain --state ./.wrkr/state.json --json > ./.wrkr/verify.json
```

### Step 5: (Optional but recommended) Define "production" deterministically

Auditors hate heuristics like "contains prod". Define production targets explicitly, then compute production-write tooling.

Create a production targets file and run:
```bash
wrkr scan --path /path/to/repos --state ./.wrkr/state.json --production-targets ./production-targets.v1.yaml --json > ./.wrkr/scan.json
```

See `docs/examples/production-targets.v1.yaml` for a starting point.

## What You Still Need (Non-Wrkr Workstreams)

Wrkr can help you close the engineering evidence gap quickly. You still need owners for:
- Role and scope mapping (which systems are in scope and why).
- Technical documentation and evaluation evidence for each in-scope system (model/system docs, testing, limitations, monitoring).
- Human oversight procedures that are actually operational.
- Incident reporting and response playbooks with logs and drills.
- Supplier management and contract evidence for third-party AI components.

## 30/60/90 Day Plan (Blunt)

### 0-30 days: inventory + evidence + drift gate
- Run `wrkr scan` across your critical repos/org and store artifacts.
- Stand up a `wrkr regress` baseline and gate drift in CI for the repos that matter.
- Identify your top 5 "write-capable" tools and decide: approve with controls, reduce permissions, or remove.

### 30-60 days: production targets + approvals + remediation
- Define production targets explicitly and compute `production_write` subset.
- Put approvals and lifecycle state transitions into a documented process.
- Remediate the highest-risk pathways (credential access + headless execution + write permissions).

### 60-90 days: operationalize and rehearse
- Run a tabletop: "Auditor asks for evidence on date X." Produce it live.
- Make the evidence pack reproducible: same inputs -> same outputs.
- Integrate into your GRC system as a recurring control with owners.

## Frequently Asked Questions

### What should I prepare for an EU AI Act audit in 10 minutes?

Produce a deterministic evidence pack:
- `wrkr scan --json` inventory (`.wrkr/scan.json`)
- `wrkr scan --report-md` human summary (`.wrkr/scan-summary.md`)
- `wrkr regress run --json` drift result (`.wrkr/regress-run.json`)
- `wrkr verify --chain --json` integrity proof (`.wrkr/verify.json`)

### What will an auditor ask about AI agents and dev tools?

They will ask for:
- Your inventory of AI tooling across repos and CI execution contexts.
- Which tools can write code, deploy, or change infrastructure.
- Which tools can access credentials or production endpoints.
- Evidence that you detect and respond to changes (drift gates, approvals).

Wrkr covers the deterministic inventory and evidence trail for the SDLC tooling layer.

### How do I prove which tools can touch production?

Define production targets explicitly with `--production-targets`, then run `wrkr scan` and use the `production_write` budget summary.

If you do not configure targets, you can still report "write-capable" and "credential-capable" tooling, but you cannot claim the production subset with confidence.

### What does Wrkr not cover for EU AI Act compliance?

Wrkr does not:
- classify your AI system category under the EU AI Act
- generate your technical documentation for model/system obligations
- validate your training data governance or evaluation methodology

Wrkr does:
- discover AI dev tooling and execution contexts
- compute privilege budgets and production-write subsets (when configured)
- emit deterministic evidence artifacts and drift signals

### How do I operationalize this for a CISO or Head of GRC?

Treat it like a control:
- owner: engineering security / platform
- cadence: weekly scan + CI drift gate
- evidence: store `.wrkr/*.json` and `.wrkr/*.md` outputs
- response: documented approval/remediation workflow when drift is detected (exit code 5)
