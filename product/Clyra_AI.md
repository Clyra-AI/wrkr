# Clyra AI — Clarity, Consistency, Coherence

## The Prescription

You cannot control what you cannot prove. You cannot prove what you cannot see.

**See → Prove → Control.**

This is not a tagline. It is the sequence every organization will follow as AI agents move from pilot to production. It is the same sequence enterprises followed for cloud (Datadog → Vanta → Wiz) and containers (Trivy → Sigstore → OPA/Falco). The infrastructure paradigm changes. The governance sequence does not.

The first three verbs are the foundation. What comes after — **Pay** and **Trust** — follows naturally when proof becomes infrastructure. Transactions don't settle without verified execution. Insurance doesn't underwrite without auditable evidence. The full sequence is See → Prove → Control → Pay → Trust, but the first three must be real before the last two are possible.

Clyra AI builds the governance infrastructure layer for the AI era. Three products, one shared proof primitive, one thesis: the company that owns the proof layer owns the trust layer.

---

## The Thesis

### Why now

We are in Year 2–3 of AI-assisted development adoption. 85–90% of developers use AI coding tools. 81% of teams are deploying AI agents. Only 14% have security approval for what they're deploying. 88% of organizations report confirmed or suspected AI agent security incidents.

The EU AI Act begins broad enforcement August 2, 2026. Texas TRAIGA is already active. Colorado's AI Act takes effect June 2026. NIST published its AI agent security RFI in January 2026. SOC 2 auditors have updated their control matrices with AI-specific line items.

The regulatory clock is ticking on a problem most organizations cannot answer: *What AI tools are in our environment? Can we prove they're governed? Can we stop them when they go wrong?*

Every infrastructure paradigm shift produces the same pain sequence: visibility gap → security gap → governance gap → supply chain gap → platform engineering. Cloud produced Datadog, Wiz, HashiCorp, Vanta. Containers produced Trivy, Falco, Sigstore, Backstage. AI-assisted development will produce its own category-defining companies. The window is open now and closes as incumbents extend.

### Why primitives

Peter Diamandis and Alex Wissner-Gross argue in *Solve Everything* that the only durable investment thesis remaining is infrastructure primitives — the tooling layer that application engineers build on top of. Applications compete on features. Primitives compete on adoption. Features can be copied. Adopted formats and protocols cannot be displaced without breaking everything built on top of them.

Every lasting infrastructure company shipped a primitive inside the product:

| Company | The App | The Primitive |
|---------|---------|---------------|
| HashiCorp | Terraform CLI | HCL language + state format |
| Sigstore | cosign CLI | Signing spec + transparency log protocol |
| Docker | Docker CLI | Container image format (OCI) |
| Open Policy Agent | OPA CLI | Rego language + policy evaluation protocol |
| Snyk | Snyk CLI | Vulnerability database format |

The app gets users. The primitive gets the moat. When third parties start producing or consuming your format, the moat widens with every adopter and you stop competing on features entirely.

Clyra AI builds three apps. Underneath all three sits one shared proof primitive. If that primitive becomes what auditors expect, what agent frameworks emit, and what CI pipelines verify — Clyra AI owns the trust layer for AI infrastructure regardless of which specific tools win the application race above.

### Why neutral

The vendor that sells you the complexity is never the one that governs it. AWS did not build Datadog. Azure did not build Wiz. Google did not build Trivy. The platform provider is incentivized to make adoption easy, not governance tight.

Anthropic will not build governance for Cursor. OpenAI will not build governance for Windsurf. No model provider will build cross-surface compliance evidence. The governance layer must be neutral — a third party that sees all surfaces, all frameworks, all agents, and speaks the auditor's language.

Clyra AI is that neutral layer.

---

## The Products

### Wrkr — See

**What AI tools are in your environment?**

Wrkr is an open-source Go CLI that discovers AI development tools across your organization. Scan your GitHub org, see every AI tool, agent, plugin, MCP server, and configuration in 10 minutes. No integration required — read-only scan of code, configs, and CI pipelines.

Wrkr answers the questions every CISO is being asked and cannot answer today:

- What AI tools are our developers using?
- Which ones have production access?
- Which ones were never approved?
- What are the top 5 risks?

Wrkr is the front door. It produces the "holy shit" moment — the scan that reveals 31 AI tools nobody knew about, three of them with unapproved write access to production databases. That moment creates the budget conversation.

**The wedge:** 10-minute time-to-first-value. No agents to deploy, no integrations to configure. Connect your GitHub org and see the truth. This is the Wiz playbook — show the mess before asking anyone to change anything.

**The buyer:** CISO and VP Engineering, using existing AppSec and compliance budget.

**OSS → Enterprise:** Free CLI scans and produces evidence bundles. Wrkr Pro adds continuous monitoring, scheduled scans, Slack alerts, dashboard, SIEM export, approval workflows.

---

### Axym — Prove

**Can you prove what your AI systems did and that appropriate controls were in place?**

Axym is an open-source Go CLI that captures structured evidence of AI system behavior and produces audit-ready compliance packages mapped to EU AI Act, SOC 2, SOX, PCI-DSS, and state AI regulations.

Axym solves the evidence gap. The EU AI Act does not require dashboards — it requires proof. Signed, structured, verifiable proof that AI systems operated within approved boundaries, that risk management controls were in place, that human oversight occurred. Most organizations have zero machine-readable evidence of any of this.

Axym intercepts AI agent activity at the integration layer — CI/CD pipelines, MCP server calls, API gateways, tool invocations, data pipeline runs — and produces structured, signed, tamper-evident proof records. These records are then mapped against specific regulatory controls to generate audit-ready compliance packages.

**The job:** Turn "we have an AI policy" into "here are 1,400 signed proof records proving every agent action operated within approved parameters, mapped to EU AI Act Articles 9, 12, 13, 14, and 15. The audit closes in three days instead of three weeks."

**The buyer:** Head of GRC and Chief Compliance Officer, using existing GRC and audit budget. The platform engineer integrates it; the compliance team funds it.

**OSS → Enterprise:** Free CLI captures evidence and generates bundles. Axym Pro adds continuous evidence collection, compliance dashboard, regulatory deadline tracking, GRC platform export (Vanta, Drata, ServiceNow), auditor portal.

**Clyra DNA:** Axym absorbs the production-hardened evidence architecture from the original Clyra evidence project (the predecessor codebase) — the canonicalization specs, the digest algorithms, the replay certification tiers (A/B/C), the OSCAL v1.1 compliance mappings, the "evidence loss budget = 0" durability model. The dbt-to-Snowflake data pipeline use case (SOX, PCI-DSS) becomes an Axym collector, extending Axym's reach from AI agent governance into data pipeline governance. One evidence engine, multiple regulatory surfaces.

---

### Gait — Control

**Can you stop an AI agent before it causes damage?**

Gait is an open-source Go CLI that sits at the tool boundary of AI agents — not the prompt boundary, the tool boundary. It enforces fail-closed policy before high-risk actions execute and captures every decision as a signed, offline-verifiable artifact.

Gait answers the question that follows discovery and evidence: *Now that we know what's running and can prove what happened, how do we prevent the next incident?*

Most governance tools can watch. Gait can stop. Non-allow means non-execute. The signed trace proves the decision. The regression framework ensures you never debug the same failure twice.

**Already shipped and in the open.** Gait is not a roadmap item. It has a real CLI, real signed packs, real MCP integration, real policy enforcement, real regression tooling, real voice agent gating. 2,880 tool calls gate-checked in 24 hours in a documented production scenario.

**The buyer:** VP Engineering and CISO, using existing security and AppSec budget.

**OSS → Enterprise:** Free CLI enforces policy and produces signed packs. Gait Pro adds fleet-wide policy management, centralized pack storage, team dashboards, SIEM integration.

---

## How They Fit Together

### The Governance Sequence

Each product is independently useful. Together, they form a complete governance loop.

```
                    ┌─────────────────────────┐
                    │                         │
          ┌────────▼────────┐                 │
          │      WRKR       │                 │
          │      See        │                 │
          │                 │                 │
          │  Discover AI    │                 │
          │  tools, agents, │                 │
          │  risks          │                 │
          └────────┬────────┘                 │
                   │                          │
                   │  findings feed           │
                   │  proof pipeline       │
                   │                          │
          ┌────────▼────────┐                 │
          │      AXYM       │                 │
          │      Prove      │                 │
          │                 │                 │
          │  Capture agent  │                 │
          │  evidence, map  │                 │
          │  to compliance  │                 │
          └────────┬────────┘                 │
                   │                          │
                   │  gaps inform             │
                   │  policy rules            │
                   │                          │
          ┌────────▼────────┐                 │
          │      GAIT       │                 │
          │      Control    │                 │
          │                 │                 │
          │  Enforce policy │                 │
          │  at tool        │                 │
          │  boundary       │                 │
          └────────┬────────┘                 │
                   │                          │
                   │  enforcement decisions   │
                   │  become proof          │
                   └──────────────────────────┘
```

**Wrkr discovers** that a Claude Code agent has unapproved write access to production Postgres via MCP. **Axym captures proof** of every action that agent takes and maps it to EU AI Act Article 14 (human oversight). **Gait enforces** a fail-closed policy that blocks write operations without signed approval. Gait's enforcement decision becomes a proof record in Axym. Axym's compliance gap report informs Gait's policy rules. Wrkr's next scan detects the policy is now in place and updates the risk score.

The loop closes. Each product feeds the others.

### The Sales Sequence

The products also form a natural sales progression:

1. **Wrkr gets you in the door.** The 10-minute scan produces findings that alarm the CISO. Budget conversation starts.
2. **Axym captures the compliance deal.** The CISO says "we need to prove governance for the auditor." Axym generates the evidence package. GRC budget activates.
3. **Gait closes the control gap.** The board says "prove it won't happen again." Gait enforces policy and proves every decision. Security budget activates.

Each sale funds the next conversation. Each product creates pull for the next.

---

## The Flywheel

### Product Flywheel

```
More Wrkr scans → more AI risks discovered →
more urgency for compliance evidence → more Axym adoption →
more evidence of what agents do → more demand for enforcement →
more Gait adoption → more enforcement data as evidence →
richer Axym compliance bundles → more auditor trust →
more compliance deals → more Wrkr scans to expand scope → ...
```

### Primitive Flywheel

This is the flywheel that matters most and takes longest to spin.

All three products share one primitive — the Clyra AI proof record format (`Clyra-AI/proof`), published as a standalone Go module and language-agnostic JSON Schema spec.

```
Clyra AI CLIs produce proof records →
auditors learn to expect the format →
agent frameworks embed the format at source →
more producers of proof records →
more demand for tooling that consumes them →
Clyra AI CLIs are the canonical consumers →
more adoption of Clyra AI CLIs →
more proof records in the ecosystem → ...
```

The critical inflection: **when proof records are produced by tools Clyra AI did not build.** When a MCP server emits proof records natively. When a LangChain callback produces a signed proof record. When an auditor's verification tool validates proof-format bundles as a standard operation. At that point, the format is the moat and Clyra AI is the reference implementation.

This is how Sigstore won. Cosign was useful. But the real moat is that every container registry now supports Sigstore signatures, every CI pipeline can verify them, and switching away would break the ecosystem.

### Community Flywheel

```
OSS CLI solves real pain → engineers adopt it →
engineers contribute detectors / collectors / framework mappings →
more coverage → more reasons to adopt →
enterprise version captures budget →
revenue funds more OSS development →
more OSS contributions → ...
```

The compliance framework mappings (EU AI Act, SOC 2, SOX, PCI-DSS, state laws) are YAML configuration files, not code. Adding a new regulation is a YAML PR to `Clyra-AI/proof`. GRC consultants, compliance engineers, and legal teams can contribute framework mappings without writing Go. This is the highest-leverage community contribution surface — every new framework mapping makes the product more valuable to a new buyer without engineering effort from Clyra AI.

---

## The Shared Primitive

### Architecture

Four repos. Three CLIs. One shared proof module.

```
Clyra-AI/proof        ← shared Go module + JSON Schema specs + compliance mappings
Clyra-AI/gait         ← Control CLI, imports Clyra-AI/proof
Clyra-AI/axym         ← Prove CLI, imports Clyra-AI/proof
Clyra-AI/wrkr         ← See CLI, imports Clyra-AI/proof
```

The `Clyra-AI/proof` repo is the foundation:

- **Record schema** — the atomic unit of proof. A structured, signed, chainable proof record with deterministic hashing, canonicalization, and versioning.
- **Hash chain** — append-only, tamper-evident sequence of records. Same mechanism as certificate transparency logs. Boring, proven, auditable. Hash chains provide stream integrity — proof that nothing was deleted or reordered over time.
- **Signing protocol** — Ed25519 + cosign integration. Offline verification without calling home.
- **Compliance framework mappings** — YAML files mapping proof record types to regulatory controls. EU AI Act, SOC 2, SOX, PCI-DSS, state AI laws. Configuration, not code.
- **JSON Schema specs** — the language-agnostic contract. Anyone can implement the spec in any language. The Go module is the reference implementation, not the only implementation.

**Two complementary integrity models.** Proof defines two integrity mechanisms that serve different purposes and should not be collapsed into one:

1. **Hash chains (stream integrity):** Each record's hash includes the previous record's hash, creating a tamper-evident sequence. Used for continuous evidence streams — proving nothing was deleted or reordered over time.
2. **Manifest+signature (artifact integrity):** A manifest lists every file in a bundle with SHA-256 digests, signed as a unit. Used for point-in-time deliverables — proving "this evidence package is intact." This model is proven by Gait's PackSpec v1.

Axym audit bundles, Wrkr evidence bundles, and Gait packs all need both: individual proof records are chain-linked for stream integrity, and the bundle as a whole is manifest-signed for package integrity. Both models coexist within the `Clyra-AI/proof` primitive.

**Extraction lineage.** The `Clyra-AI/proof` module is not built from scratch. It is extracted from Gait's production-hardened codebase — specifically `core/sign/` (~340 LOC of Ed25519 signing, verification, and key management), `core/jcs/` (~23 LOC of RFC 8785 JSON canonicalization wrapping `gowebpki/jcs`), and `core/schema/` (~1,050 LOC of JSON Schema validation and type definitions using `kaptinlin/jsonschema`). The extraction surface is deliberately small — under 1,500 LOC of extracted code (the new packages like `record` and `chain` add ~1,800 LOC of new code on top) — which means proof starts lean and correct. This is the same pattern that produced lasting infrastructure primitives: HashiCorp extracted HCL from Terraform, Docker extracted OCI from the Docker engine, Sigstore extracted `sigstore/sigstore` from cosign. Building the primitive from the code that already works in production eliminates the class of bugs where the primitive and the product produce subtly different cryptographic outputs.

### Design Principles

1. **Proof as artifact.** Every output is a file — structured, versioned, signed, portable. Not a dashboard you log into. Not a SaaS you depend on. A file you can commit, attach, verify, and archive.

2. **Primitive inside the app.** The proof record format and verification protocol are standalone — usable without any Clyra AI CLI. Agent frameworks, MCP servers, CI pipelines, and GRC platforms can adopt the format independently. The spec earns standard status through adoption by the CLIs' users, not by announcing a standard nobody uses.

3. **Deterministic pipeline.** Zero LLMs in the governance chain. Pattern matching, schema validation, cryptographic hashing. Same inputs produce same outputs, always. A governance tool that hallucinates findings or fabricates evidence is worse than no tool at all.

4. **Minimal data, maximum proof.** Capture the minimum data needed to prove compliance. Hashes, not payloads. Summaries, not transcripts. Digests, not raw SQL. The proof record proves the control was in place without creating a new data liability.

5. **Offline-first.** Core workflows — verify, diff, replay, regress — work without network access. Air-gapped environments are first-class. No phone-home, no cloud dependency for the governance chain.

6. **Fail-closed.** When in doubt, block. Ambiguous policy evaluations do not default to allow. Missing evidence does not default to compliant. This is a trust decision — better to over-restrict than to silently permit.

7. **Extract, don't greenfield.** Shared primitives are extracted from production-proven product code, not designed in isolation. Proof is extracted from Gait's battle-tested signing, canonicalization, and schema validation. This is how durable infrastructure primitives are built — from code that already works, not from specifications that haven't been tested under load. Build the product, find the primitive, extract it.

8. **Adapter-first integration.** Clyra AI products wrap existing tools — they never require upstream changes to agent frameworks, MCP servers, or CI pipelines. Subprocess calls, sidecar proxies, log readers, API middleware. Zero upstream PRs required. The moment you ask a framework maintainer to install your SDK, you've lost six months. Gait proved this with eight reference integrations across agent frameworks. Wrkr and Axym follow the same pattern: read existing artifacts and outputs, don't ask anyone to change how they work.

9. **Regress everything.** The regression pattern — converting a known-bad state into a permanent CI fixture — is a cross-product capability, not a Gait-specific feature. Gait converts bad runs into enforcement regression fixtures. Axym converts compliance gaps into coverage regression fixtures. Wrkr converts unapproved tool postures into inventory regression fixtures. The pattern is: capture the bad state, define the expected behavior, fail CI if the bad state recurs. "Never debug the same failure twice" applies to compliance posture and tool inventory just as much as policy enforcement.

10. **Exit codes are API.** CI pipelines consume governance decisions through exit codes, not JSON output or dashboards. All Clyra AI CLIs share a common exit code vocabulary defined in `Clyra-AI/proof`: `0` success, `1` internal error, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift detected, `6` invalid input, `7` dependency missing, `8` unsafe operation blocked. When `wrkr scan` returns exit 5, it means the same class of thing as when `gait regress run` returns exit 5.

11. **Thin adoption layers.** Non-Go SDKs (Python, TypeScript) are thin wrappers over the Go CLI via subprocess or the JSON Schema spec. Zero logic in the wrapper. All deterministic behavior lives in Go. The moment logic diverges across language implementations, determinism breaks and cross-platform verification becomes a compatibility testing nightmare. Gait settled this with its Python SDK — a subprocess wrapper with a 30-second timeout, zero business logic, structured JSON parsing of CLI output — and the pattern holds for all products.

---

## The Market Position

### What Clyra AI is

- **The governance infrastructure layer for AI.** Three products covering the full See → Prove → Control sequence.
- **A proof company.** The atomic unit is the signed proof record. Everything else — discovery, compliance mapping, policy enforcement — serves the goal of producing and consuming trustworthy proof.
- **A primitives company that ships apps.** The apps get users. The proof format gets the moat. Both are essential. Neither is sufficient alone.
- **Neutral.** Clyra AI governs AI tools from every vendor — Anthropic, OpenAI, Google, open-source. The governance layer cannot be owned by any platform provider.

### What Clyra AI is not

- **Not a model provider.** Clyra AI does not host, train, or serve AI models.
- **Not an agent framework.** Clyra AI does not orchestrate AI agents. It governs them at the boundary.
- **Not an observability platform.** Clyra AI does not replace Datadog, LangSmith, or Arize for operational debugging. It produces compliance-grade evidence, not operational telemetry.
- **Not a GRC platform.** Clyra AI does not replace Vanta or Drata for compliance workflow management. It produces the evidence that GRC platforms consume.
- **Not AI-powered.** The governance pipeline is deterministic. No LLMs in the evidence chain. This is deliberate — auditors must trust the proof mechanism itself.

### Where Clyra AI sits in the stack

```
┌─────────────────────────────────────────────────────────┐
│                    AI Applications                       │
│              (ChatGPT, Claude, Copilot, ...)             │
├─────────────────────────────────────────────────────────┤
│                    Agent Frameworks                       │
│         (LangChain, CrewAI, OpenAI Agents, ...)          │
├─────────────────────────────────────────────────────────┤
│         ┌──────────────────────────────────┐            │
│         │       Clyra AI Governance        │            │
│         │                                  │            │
│         │  Wrkr: See                       │            │
│         │  Axym: Prove                     │            │
│         │  Gait: Control                   │            │
│         │                                  │            │
│         │  Proof Primitive                 │            │
│         └──────────────────────────────────┘            │
├─────────────────────────────────────────────────────────┤
│                    Infrastructure                        │
│            (Models, Compute, Cloud, Data)                 │
└─────────────────────────────────────────────────────────┘
```

Clyra AI sits between the agent frameworks and the infrastructure. It does not control what agents think. It governs what agents do.

---

## The Competitive Moat

### Layer 1: Product moat (12–18 months)

Each CLI solves a real problem faster than alternatives. Wrkr scans in 10 minutes. Axym generates an audit bundle in 15 minutes. Gait enforces policy with signed proof. Speed-to-value and artifact quality are the early differentiators.

### Layer 2: Data moat (18–36 months)

As organizations run Clyra AI tools continuously, they accumulate evidence history. The compliance maps, risk trends, enforcement records, and audit bundles become institutional knowledge. Switching costs increase with every quarter of evidence captured.

### Layer 3: Format moat (24–48 months)

This is the endgame. When auditors expect proof-format evidence bundles. When agent frameworks emit proof records natively. When GRC platforms import proof-format bundles as a standard connector. When CI pipelines verify proof-format integrity as a built-in step. At this point, Clyra AI is not competing on features — it is the format. Displacing it requires breaking every tool that depends on it.

The format moat is why the primitives thesis matters. Features can be copied in a quarter. An adopted format takes years to displace.

---

## The Business

### Revenue model

Each product follows the same pattern:

| Layer | What | Revenue |
|-------|------|---------|
| **OSS CLI** | Full-featured CLI, local-only, unlimited use | Free forever |
| **Pro** | Dashboard, continuous monitoring, team features, SIEM/GRC export, SSO/RBAC | Annual subscription, per-org |
| **Enterprise** | Dedicated support, validated compliance mappings, custom framework development, auditor training | Annual contract |

The OSS CLI is the distribution channel. Pro captures the budget when the CISO asks for a dashboard and continuous monitoring. Enterprise captures the budget when the Head of GRC needs legally validated compliance mappings and auditor-facing deliverables.

### Budget mapping

Clyra AI maps to existing purchasing authority — no new budget category required:

| Buyer | Budget Line | Clyra AI Product |
|-------|-------------|------------|
| CISO | AppSec / AI security | Wrkr Pro |
| Head of GRC | Compliance / audit | Axym Pro |
| VP Engineering | Security tooling / platform | Gait Pro |
| CFO (via GRC) | Audit cost reduction | Axym Enterprise |

### Go-to-market sequence

1. **Wrkr OSS launches.** "We scanned our org and found 31 AI tools we didn't know about." Hacker News, r/netsec, r/devops. Bottom-up adoption by security engineers.
2. **Axym OSS launches.** "We ran an AI compliance audit on ourselves. Here's what was missing." GRC-focused LinkedIn, compliance conferences, auditor outreach. Bottom-up adoption by platform engineers, pulled in by GRC teams.
3. **Gait is already live.** Referenced in every Wrkr and Axym conversation as proof that Clyra AI builds real tools, not slide decks.
4. **Design partners.** 5–10 organizations facing EU AI Act audits in Q3–Q4 2026. Run all three products. Validate the evidence format with their auditors.
5. **Pro launches.** Dashboard, continuous monitoring, alerting. Captures the enterprise budget that the OSS CLI created.
6. **Primitive spreads.** Publish SDKs wrapping the proof module for Python, TypeScript. Pitch to agent framework maintainers: "Add 3 lines, your users get compliance evidence for free." Every new producer of proof records is a new customer for Clyra AI's compliance mapping and verification tooling.

---

## What Winning Looks Like

### Year 1

- Three OSS CLIs with active communities and real production usage
- Proof record format adopted by 10+ organizations
- First audits closed using Clyra AI evidence bundles
- First Pro revenue from compliance-driven buyers
- Regulatory enforcement (EU AI Act August 2026) validates the thesis publicly

### Year 2

- Proof record format emitted natively by 5+ agent frameworks or MCP servers
- Auditors at 2+ Big 4 firms recognize Clyra AI evidence bundles
- Clyra AI compliance framework mappings contributed by the community for 10+ regulations
- Platform deal: organization deploys all three products as unified governance stack

### Year 3

- The proof record format is the de facto standard for AI compliance evidence
- GRC platforms (Vanta, Drata, ServiceNow) build native Clyra AI evidence import connectors
- Clyra AI is to AI governance what Datadog is to cloud observability — the neutral, multi-surface, category-defining platform
- The proof layer is the trust layer, and Clyra AI owns it

---

## Strategic Horizons

Years 1–3 establish the foundation: See → Prove → Control. The horizons below extend the primitive into settlement, insurance, and cross-organizational trust. Each horizon is additive to the existing architecture — no new repos, no new buyer conversations, just deeper leverage from the proof record format already in production.

### H3 — PolicyGraph (Clyra AI, enterprise tier)

**Goal:** Unify eligibility control across pipelines and agents.

PolicyGraph is the centralized control plane that sits on top of Gait's per-repo policy enforcement. Where Gait enforces policy at the individual tool boundary, PolicyGraph manages the policy estate across the organization.

Capabilities:

- **Policy version service** — centralized policy registry with versioned rollout, canary deployment, and rollback. Teams consume policies; GRC owns the definitions.
- **SoD rules** — cross-agent separation of duties. "The agent that writes production code cannot approve its own deployment." Enforced across the governance stack, not just within a single tool.
- **Freeze windows** — organization-wide deployment freeze periods enforced at the policy layer. Gait blocks tool calls during freeze windows; PolicyGraph defines and distributes the windows.
- **Data-class rules** — policy rules scoped to data sensitivity. Agents accessing `credentials` or `pii` data classes (as tagged by Wrkr) face stricter policy constraints than agents accessing `internal` data.
- **Policy change logs** — every policy modification is a signed proof record. Who changed what, when, why, with what approval. The policy estate itself becomes auditable evidence.

**Impact:** Clyra becomes the Tier-2 control plane for enterprises — not just governing individual agents, but governing the governance policies themselves.

### H4 — Proof-to-Pay (commercial)

**Goal:** Settle payments only when proofs validate execution.

When AI agents do billable work — code written, data processed, decisions executed — the proof record becomes the settlement artifact. No valid proof chain, no payment. This turns the compliance primitive into a financial primitive.

Capabilities:

- **Proof-gated settlement** — payment rails that require verified proof chains before releasing funds. The proof record is the invoice line item's evidence attachment.
- **Proof-to-Insure policy overlays:**
  - Insurer-recognized evidence packs — audit bundles formatted to insurer specifications
  - Replay certification requirements for coverage — Tier A replay as a condition of underwriting
  - Attestation tokens as underwriting inputs — proof chain integrity scores inform policy pricing
  - "Provable agent" eligibility criteria — agents that emit proof records qualify for lower premiums

**Impact:** Clyra becomes the gatekeeper for AI-linked transactions. The proof record is no longer just compliance evidence — it is the settlement condition.

### H5 — Cross-Org Proof Exchange

**Goal:** Portable trust.

Proof records travel between organizations like invoices or purchase orders. When Company A hires Company B's AI agents to process data, Company A receives a signed proof chain proving how the work was executed, what policies were in place, and what controls were active. Trust is verified, not assumed.

This extends the proof format from an internal compliance tool to an inter-organizational trust protocol. The proof chain becomes the portable credential that AI service providers present to their customers.

**Impact:** The proof record format becomes the trust handshake between organizations in the autonomous economy.

### H6 — Proof and Settlement Fabric

**Goal:** The global trust substrate for autonomous systems.

Capabilities:

- **Proof ledger** — persistent, queryable registry of proof chains across organizations
- **Replay-as-a-service** — third-party replay verification for high-stakes transactions
- **Attestation registry** — public registry of agent compliance attestations, queryable by counterparties
- **Adaptive risk models** — risk scoring that evolves based on proof chain history and enforcement patterns
- **Settlement rules tied to proofs** — programmable settlement logic triggered by proof chain verification

The full sequence realized: **Data → Policy → Action → Proof → Settlement.** Every consequential AI action produces a proof record. Every proof record is verifiable. Every settlement is conditional on verification.

**Impact:** Clyra becomes infrastructure. The proof record format is the common language between agents, auditors, insurers, and payment systems.
