# THE STATE OF AI TOOL SPRAWL

Q1 2026  
What 500 organizations do not know about the AI tools in their environment  
Clyra AI Research  
clyra.ai  
Methodology: Wrkr Open Source Scanner ([github.com/Clyra-AI/wrkr](https://github.com/Clyra-AI/wrkr))

## 1. Headline Findings

The opening punch. Three to five numbers that stop the scroll and can stand alone in press coverage.

### Format

- Single page with large metrics and one-sentence context each.
- Numbers first. Methodology and caveats appear in Section 2.

Example headline set:
- `X` AI tools discovered across `Y` organizations scanned.
- `Z%` of discovered tools were never formally approved.
- `N` organizations had prompt-channel poisoning indicators in agent instructions or CI prompt assembly.
- `M` critical cross-agent attack paths connected external entry points to internal high-privilege targets.
- `P%` of MCP servers in enrich mode matched advisories or untrusted registry posture (reported with `as_of` timestamp).

### Wrkr Output Required

- Campaign aggregate totals and prevalence rates.
- Approval status distribution and production-write exposure counts.
- Prompt-channel prevalence metrics.
- Top attack-path metrics (`count`, `max path_score`, prevalence by org).
- Enrich-only MCP advisory/registry prevalence with explicit `as_of` and source provenance.

### PR Value

This is the screenshot page for journalists and boards. Every number must be independently reproducible from exported artifacts.

## 2. Methodology

The credibility anchor. Transparent and reproducible.

### Format

- One page maximum.
- Explicitly separate two scan modes:
- `offline deterministic baseline` (default).
- `optional enrich mode` (network lookups, non-deterministic over time).
- Cover scope boundaries, detector classes, and data handling.

### Wrkr Output Required

- Scan metadata: run timestamp, Wrkr version, scan duration, counts, detector list.
- Mode metadata: whether enrich was enabled, enrich sources, and `as_of` capture window for enrich evidence.
- Determinism statement for default mode and claim restrictions for enrich-derived findings.

### PR Value

Research trust depends on reproducibility. This section must make clear what is deterministic and what is time-sensitive.

## 3. AI Tool Inventory Breakdown

Core inventory intelligence by category.

### Format

- Categorized data tables with commentary:
- AI coding assistants.
- AI agents and frameworks.
- MCP servers and integrations.
- Plugins/extensions and CI agents.
- API/model provider integrations.
- Prompt-channel risk signals (instruction overrides, hidden/invisible characters, untrusted context assembly patterns).
- For each category: count, prevalence, common tools/signals, least expected findings.

### Wrkr Output Required

- Per-tool/per-signal records: name, type, category, location, repo/org, detector, confidence class or deterministic reason class.
- Prompt-channel finding families with stable reason codes.

### PR Value

Adds depth behind headline statistics and gives concrete examples reporters can cite.

## 4. Privilege and Access Map

Converts discovery into risk by showing what tools can do and how abuse chains compose.

### Format

- Risk-tiered findings by severity:
- `CRITICAL`: production write, credential store access, infrastructure provisioning, or critical composed attack path.
- `HIGH`: sensitive read exposure, secret access with weak controls, high-path amplification.
- `MEDIUM`: broad staging/dev permissions and moderate path potential.
- `LOW`: read-only or tightly constrained posture.
- Include a dedicated "Top Cross-Agent Attack Paths" block with top `N` composed chains.

### Wrkr Output Required

- Permission surface per tool (write targets, credential access, infrastructure scope, data class).
- Attack-path artifacts with deterministic fields:
- `path_id`, `entry_surface`, `pivot_surfaces`, `target_surface`, `path_score`, `amplifiers`, `reason_codes`.

### PR Value

This section drives action and budget. It ties inventory to credible exploitability and business impact.

## 5. The Approval Gap

Quantifies governance gaps between approved and organically adopted tooling.

### Format

- Approved vs unapproved vs unknown tool posture.
- Org-level vs developer-level adoption patterns.
- Overlay high-risk subsets:
- unapproved tools with prompt-channel findings.
- unapproved tools present in critical attack paths.

### Wrkr Output Required

- Approval classification per tool.
- Adoption-pattern classification.
- Cross-table joins to prompt-channel and attack-path evidence.

### PR Value

Produces a quotable governance ratio and a clear remediation target.

## 6. Regulatory Exposure Analysis

Maps findings to control obligations and evidence gaps.

### Format

- Regulation-by-regulation gap analysis:
- EU AI Act (Articles 9, 12, 14, 15).
- SOC 2 updates.
- Colorado AI Act, Texas TRAIGA, NIST AI RMF alignment.
- Include prompt-channel and attack-path risk as risk-management and oversight evidence signals.

### Wrkr Output Required

- Control mappings and gap rows by regulation/control/tool.
- Evidence linkage to findings, path records, approvals, and proof records.

### PR Value

Moves the narrative from security concern to deadline-driven compliance exposure.

## 7. Case Studies (Anonymized)

Three to five specific narratives that turn data into recognizable incidents.

### Format

- 200-300 words each:
- Org profile (anonymized).
- Discovery details.
- Risk/impact scenario.
- Corrective action path.
- Ensure at least one prompt-channel case and one cross-agent attack-path case.

### Wrkr Output Required

- Per-org anonymized exports with detailed signal and path context.
- Evidence provenance preserved while removing identifiers.

### PR Value

Case studies create recall and media pickup.

## 8. Benchmarks and Comparisons

Provides historical and segment context that validates category significance.

### Format

- Compare AI tool sprawl trajectory to cloud/container/SaaS sprawl.
- Segment cuts by org size, vertical, and scan scope.
- Add trend benchmarks for:
- prompt-channel finding prevalence.
- critical attack-path prevalence.
- enrich advisory prevalence (with `as_of` window).

### Wrkr Output Required

- Segment-level campaign metrics and trend deltas.

### PR Value

Positions AI tool sprawl as an established infrastructure and governance category.

## 9. Recommendations

Action list that is independently valid and operationally specific.

### Format

Seven recommendations max:
1. Establish full AI tool inventory as the first control.
2. Classify by privilege and composed attack-path risk, not tool brand.
3. Add prompt-channel static scanning to SDLC governance baselines.
4. Run continuous scans and drift gates.
5. Map evidence to regulatory controls before audit windows.
6. Use enrich mode for MCP supply-chain decisions with explicit `as_of` provenance.
7. Integrate findings into AppSec, platform, and GRC workflows.

Closing line: Wrkr OSS scanner available at [github.com/Clyra-AI/wrkr](https://github.com/Clyra-AI/wrkr).

### Wrkr Output Required

- Derived from measured gaps in Sections 1-8.

### PR Value

Functions as the practical CTA without reading as product marketing copy.

## 10. Appendix: Full Data Tables

Raw data for analysts, researchers, and technical press.

### Format

- Downloadable JSON/CSV tables including:
- inventory rows.
- privilege rows.
- approval-gap rows.
- regulatory rows.
- prompt-channel rows.
- attack-path rows.
- enrich MCP advisory/registry rows with `as_of` and source.
- detector coverage list and methodology notes.

### Wrkr Output Required

- Full anonymized aggregate tables suitable for third-party analysis.

### PR Value

Makes the report citable and extensible by third parties.

## Working Backwards: Wrkr Output Requirements

| Report Section | Wrkr Capability | Status / Gap |
|---|---|---|
| Headlines | Aggregate statistics across multi-org scans | Implemented baseline; maintain deterministic aggregate contracts |
| Headlines | Prompt-channel prevalence metrics | Gap; covered by `OWASP-E1` stories |
| Headlines | Critical attack-path metrics | Gap; covered by `OWASP-E2` stories |
| Headlines | Enrich advisory prevalence with provenance | Partial (`--enrich` placeholder); covered by `OWASP-E3` stories |
| Methodology | Deterministic baseline vs enrich mode provenance fields | Partial; add explicit mode metadata and `as_of` guidance |
| Tool Inventory | Prompt-channel category and reason-code breakdown | Gap; add new detector outputs |
| Privilege Map | Attack-path chain scoring and top-path export | Gap; add graph + path scoring outputs |
| Approval Gap | Cross-join with prompt-channel and attack-path risk overlays | Gap; add aggregate join fields |
| Regulatory | Mapping that includes prompt/channel and composed-path evidence | Partial; expand mapping evidence model |
| Case Studies | Anonymized detailed per-org outputs for new capabilities | Partial; add prompt/path rows to appendix export |
| Benchmarks | Segment-level metrics for prompt/path/enrich prevalence | Gap; add segment metrics in campaign aggregate |
| Appendix | Extended tabular export (`prompt_channel_rows`, `attack_path_rows`, `mcp_enrich_rows`) | Gap; add schema and export wiring |

## Report Production Checklist

1. Run deterministic baseline scans for the target campaign sample.
2. If publishing supply-chain advisory claims, run enrich scans and capture `as_of` window.
3. Aggregate campaign outputs and generate public markdown summary.
4. Export anonymized appendix tables including prompt/path/enrich rows.
5. Validate publication guardrails:
- no production-write claims without configured targets.
- no enrich-derived claims without enrich provenance fields.
- no prompt/path claims unless corresponding rows are present.
6. Draft case studies from anonymized high-signal findings (include prompt and path examples).
7. Build regulatory mapping tables and benchmark comparisons.
8. Package report artifacts plus methodology note (commit SHA, run window, mode details).
9. Stage distribution with visuals derived from reproducible metrics.
10. Publish and retain artifact bundle for independent verification.
