
THE STATE OF AI TOOL SPRAWL
Q1 2026
What 500 organizations don't know about the AI tools in their environment
Clyra AI Research
clyra.ai
Methodology: Wrkr Open Source Scanner (github.com/Clyra-AI/wrkr)

1. Headline Findings
The opening punch. 3-5 numbers that make the reader stop scrolling. These are the stats that become the headline in trade press coverage and the subject line in CISO email forwards.

1. HEADLINE FINDINGS
Format: Single page. Large bold numbers with one-sentence context each. No preamble, no methodology, no caveats. Numbers first, explanation later. Example structure:• "X AI tools discovered across Y organizations scanned"• "Z% of discovered tools were never formally approved"• "N tools had direct write access to production databases"• "M organizations had zero visibility into their AI tool inventory"• "P% of discovered tools would fail EU AI Act Article 15 transparency requirements"
Wrkr Output Required
Aggregated scan statistics: total tools discovered, approval status breakdown, permission classifications (read/write/admin), production access flags, per-org averages.
PR Value
This is the page journalists screenshot. The page CISOs forward to their board. Every number must be independently verifiable from the underlying scan data. Each stat should be alarming enough to stand alone as a social media post.


2. Methodology
Establishes credibility before the detailed findings. Short, transparent, reproducible. The reader needs to trust the numbers before they act on them.

2. METHODOLOGY
Format: One page maximum. Cover:• What was scanned: number of GitHub orgs, repos, CI pipelines, config files• How detection works: pattern matching against known AI tool signatures, MCP server configs, agent framework imports, plugin manifests• Scope boundaries: what Wrkr detects vs. what it does not claim to detect• Data handling: read-only scanning, no code execution, no data exfiltration• Reproducibility: "Any organization can verify these findings by running wrkr scan against the same public repos"
Wrkr Output Required
Scan metadata: timestamp, Wrkr version, scan duration, repo count, file count processed, detector list with version numbers.
PR Value
Credibility anchor. Security researchers and journalists will check this section first. If the methodology is transparent and reproducible, the findings are treated as research. If it is vague, they are treated as marketing.


3. AI Tool Inventory Breakdown
The core data table. A categorized inventory of every type of AI tool discovered, with counts, prevalence, and classification. This is where the scan data becomes intelligence.

3. AI TOOL INVENTORY BREAKDOWN
Format: Categorized data tables with commentary. Categories:• AI coding assistants (Copilot, Cursor, Windsurf, Cody, etc.)• AI agents and agent frameworks (LangChain, CrewAI, OpenAI Agents SDK, Autogen)• MCP servers and tool integrations• AI plugins and extensions (IDE plugins, browser extensions, CI plugins)• AI API keys and model provider integrations (OpenAI, Anthropic, Google, etc.)• Custom/internal AI tools and wrappersFor each category: count, percentage of orgs where found, most common tools, least expected findings.
Wrkr Output Required
Per-tool detection output: tool name, tool type, category, source file path, repo, org, detection confidence score, detector that triggered.
PR Value
Gives depth to the headline numbers. Journalists use this for the "for example" paragraph. CISOs use this to check if their own stack is represented. The "least expected findings" subsection is where the memorable anecdotes come from.


4. Privilege and Access Map
The section that converts discovery into risk. Not just what tools exist, but what they can do. This is where the CISO's blood pressure rises.

4. PRIVILEGE AND ACCESS MAP
Format: Risk-tiered findings. Organize by severity:CRITICAL: AI tools with production write access, credential store access, or infrastructure provisioning capabilitiesHIGH: AI tools with production read access to sensitive data, PII exposure, or unscoped API keysMEDIUM: AI tools with staging/dev environment access, broad but non-production permissionsLOW: AI tools with read-only access, sandboxed configurations, properly scoped permissionsFor each tier: count of tools, example patterns (anonymized), what the access enables, what could go wrong.
Wrkr Output Required
Permission surface analysis per tool: connected data sources, write targets, credential access, infrastructure scope, MCP server capabilities, API scopes detected in config files.
PR Value
This is the section that creates the budget conversation. "4 AI tools with production write access that were never approved" is the finding that moves purchasing authority. Without this section, the report is interesting. With it, the report is actionable.


5. The Approval Gap
Quantifies the governance vacuum. How many tools went through formal review vs. how many just appeared. The delta between what security teams think is deployed and what actually is.

5. THE APPROVAL GAP
Format: Comparison analysis.• Tools with evidence of formal approval (documented in security policies, referenced in approved tool lists)• Tools with no evidence of approval process• Tools that appear to have been individually adopted by developers without team or org-level decision• Shadow AI: tools discovered in repos that don't appear in any organizational inventory or procurement recordKey metric: the ratio of approved to unapproved AI tools. This single number tells the governance story.
Wrkr Output Required
Approval status classification per tool: approved (if matched against known-approved lists), unapproved, unknown. Adoption pattern detection: org-wide config vs. individual developer config vs. one-off usage.
PR Value
The approval gap ratio is quotable and comparable across organizations. "On average, for every 1 approved AI tool, organizations had 4.7 unapproved tools in their environment." That ratio becomes the recurring stat in every follow-up article.


6. Regulatory Exposure Analysis
Maps the findings to specific regulatory requirements. This is where the report stops being a security research piece and becomes a compliance urgency piece. Different buyer, different budget.

6. REGULATORY EXPOSURE ANALYSIS
Format: Regulation-by-regulation gap analysis.EU AI Act (enforcement August 2, 2026):• Article 9 (Risk Management): Can you demonstrate risk assessment for each AI tool? Findings: X% cannot.• Article 12 (Record Keeping): Do you have logs of AI system behavior? Findings: X% have no evidence trail.• Article 14 (Human Oversight): Can you prove human review of AI decisions? Findings: X% have no oversight mechanism.• Article 15 (Transparency): Can you document what AI tools are in use? Findings: X% had no inventory before this scan.Also cover: SOC 2 AI-specific control updates, Colorado AI Act, Texas TRAIGA, NIST AI RMF alignment.
Wrkr Output Required
Regulatory control mapping: each discovered tool mapped against whether the organization has evidence of compliance with specific regulatory articles. Gap identification per regulation per tool.
PR Value
This section is for the Head of GRC and the compliance conference circuit. It reframes the findings from "you have a security problem" to "you have a regulatory deadline in 6 months and zero evidence of compliance." Different urgency, different buyer, different budget line.


7. Case Studies
Three to five anonymized but specific narratives. These are the stories that make the data real. Reporters need anecdotes. CISOs need scenarios they recognize.

7. CASE STUDIES (ANONYMIZED)
Format: 3-5 short narratives, each 200-300 words. Structure per case:• Organization profile (size, industry, anonymized)• What was discovered (specific tools, specific access patterns)• What the risk was (what could have happened)• What they did about it (if applicable)Example angles:• "A mid-size fintech had 3 MCP servers with production database write access that no one on the security team knew existed"• "A healthcare org had AI coding tools with access to repos containing patient data pipelines"• "An open source project had 12 AI tool configurations committed by different contributors with no centralized policy"
Wrkr Output Required
Detailed per-org scan output with identifying information removed. Specific tool names, access patterns, and configuration details preserved for narrative accuracy.
PR Value
Case studies are what get quoted. The journalist picks one and leads with it. The CISO reads one and recognizes their own environment. Without this section, the report is data. With it, the report is a story.


8. Benchmarks and Comparisons
Context that makes the findings meaningful. How does the current state compare to what we know about other infrastructure paradigm shifts? This positions AI tool sprawl as a recognized category, not a novel claim.

8. BENCHMARKS AND COMPARISONS
Format: Comparative analysis.• Compare AI tool sprawl to early cloud sprawl (2014-2016): shadow IT discovery rates, time to governance maturity• Compare to container sprawl (2018-2020): unapproved images, registry proliferation, time to Sigstore adoption• Compare to SaaS sprawl: average number of unapproved SaaS tools per org vs. unapproved AI tools per org• Industry segment breakdown if sample size permits: fintech vs. healthcare vs. enterprise vs. open sourceKey framing: AI tool sprawl is following the exact same pattern as cloud and container sprawl, but the regulatory clock is moving faster.
Wrkr Output Required
Segment-level aggregation: findings broken down by org size, industry vertical (where discernible from public repo data), and scan scope.
PR Value
Establishes the category. When an analyst or reporter sees AI tool sprawl compared to cloud sprawl with data, it becomes a recognized infrastructure problem, not a startup marketing claim. This comparison is what earns the Gartner citation.


9. Recommendations
Actionable next steps that naturally lead to Wrkr adoption without being a sales pitch. The recommendations should be independently valid. Wrkr happens to be the fastest way to execute them.

9. RECOMMENDATIONS
Format: Prioritized action list. 5-7 recommendations.1. Establish an AI tool inventory before any other governance activity. You cannot govern what you cannot see.2. Classify AI tools by privilege tier (critical/high/medium/low) based on access scope, not tool category.3. Implement continuous scanning, not point-in-time audits. AI tool adoption is developer-driven and changes weekly.4. Map discovered tools to regulatory requirements now, not at audit time.5. Enforce least-privilege for AI tools at the tool boundary, not the prompt boundary.6. Build evidence trails for AI tool behavior to prepare for EU AI Act Article 12 record-keeping requirements.7. Integrate AI tool inventory into existing AppSec and compliance workflows.Closing line: "The Wrkr open source scanner used for this report is available at github.com/Clyra-AI/wrkr. Scan your own environment in 10 minutes."
Wrkr Output Required
N/A for this section. Recommendations are derived from findings, not from additional scan output.
PR Value
The recommendations are the soft CTA. Every recommendation maps to a Clyra product capability without naming it except the closing line. Readers who follow the recommendations will naturally encounter Wrkr (inventory), Gait (enforcement), and Axym (evidence). The report sells the sequence, not the product.


10. Appendix: Full Data Tables
Raw aggregated data for researchers, analysts, and journalists who want to do their own analysis. This is what makes the report citeable.

10. APPENDIX: FULL DATA TABLES
Format: Downloadable/printable data tables.• Complete tool inventory with counts and prevalence rates• Permission classification breakdown• Regulatory mapping matrix (tool type x regulation x compliance gap)• Scan metadata summary• Detector coverage list (what Wrkr looks for)• Methodology details for reproducibility
Wrkr Output Required
Full aggregated scan output in tabular format. No per-org identification. Statistical summaries suitable for third-party analysis.
PR Value
The appendix is what turns the report from content marketing into research. Analysts cite data tables. Researchers build on them. Offering the raw data (anonymized) for download increases the probability that someone else publishes findings based on your data, which generates secondary coverage without additional effort.




Working Backwards: Wrkr Output Requirements
Based on the report structure above, the following Wrkr capabilities are required to produce each section. This is the product backlog derived from the ideal report.

Report Section
Wrkr Capability
Status / Gap
Headlines
Aggregate statistics across multi-org scans
Needs: multi-org scan aggregation and summary output
Headlines
Approval status classification
Needs: approved/unapproved classification logic
Methodology
Scan metadata export (version, duration, counts, detectors)
Check: does current output include this?
Tool Inventory
Tool categorization by type (assistant, agent, MCP, plugin, API key)
Core detection exists. Check: output categorization granularity
Tool Inventory
Per-tool confidence scoring
Check: does detection output include confidence?
Privilege Map
Permission surface extraction per tool (read/write/admin, data targets)
Planned feature. Required for report.
Privilege Map
Risk tier classification (critical/high/medium/low)
Needs: classification logic based on permission surface
Approval Gap
Org-level vs. developer-level adoption pattern detection
Needs: config scope analysis (org-wide vs. individual)
Regulatory
Regulatory control mapping per finding
Uses proof primitive compliance mappings (YAML)
Case Studies
Detailed per-org output with anonymization capability
Needs: anonymized export mode
Benchmarks
Segment-level aggregation (by org size/industry)
Needs: org metadata tagging for segmentation
Appendix
Full tabular data export (CSV/JSON)
Check: current export format options



Report Production Checklist
1. Run scans against target sample (500+ public orgs/projects)
2. Aggregate data into report sections using Wrkr export capabilities
3. Draft case studies from most compelling per-org findings (anonymized)
4. Build regulatory mapping tables from scan output + compliance YAML mappings
5. Identify co-signer: security researcher or CISO to review methodology and provide foreword
6. Design report (PDF format for distribution, web version for SEO)
7. Prepare press kit: headline stats as standalone graphics, methodology one-pager, spokesperson availability
8. Stage distribution: Hacker News submission, Reddit posts, LinkedIn campaign, trade press cold emails
9. Publish on owned blog with full report download and Wrkr link
10. Follow up with business press using regulatory angle 2 weeks after initial trade press coverage
