export interface NavItem {
  title: string;
  href: string;
  children?: NavItem[];
}

export const navigation: NavItem[] = [
  {
    title: 'Start Here',
    href: '/docs',
    children: [
      { title: 'Start Here (Install)', href: '/docs/start-here' },
      { title: 'Adopt In One PR', href: '/docs/adopt_in_one_pr' },
      { title: 'Quickstart', href: '/docs/examples/quickstart' },
      { title: 'Personal Machine Hygiene', href: '/docs/examples/personal-hygiene' },
      { title: 'Security Team Workflow', href: '/docs/examples/security-team' },
      { title: 'Integration Checklist', href: '/docs/integration_checklist' },
      { title: 'Docs Source Map', href: '/docs/map' },
      { title: 'FAQ', href: '/docs/faq' },
    ],
  },
  {
    title: 'Audit Readiness',
    href: '/docs/compliance/eu_ai_act_audit_readiness',
    children: [
      { title: 'EU AI Act Prep (Auditor Checklist)', href: '/docs/compliance/eu_ai_act_audit_readiness' },
    ],
  },
  {
    title: 'Intent Guides',
    href: '/docs/intent/scan-org-repos-for-ai-agents-configs',
    children: [
      { title: 'Scan Org Repos', href: '/docs/intent/scan-org-repos-for-ai-agents-configs' },
      { title: 'Detect Headless Risk', href: '/docs/intent/detect-headless-agent-risk' },
      { title: 'Detect Prompt + Attack Paths', href: '/docs/intent/detect-prompt-channel-and-attack-path-risk' },
      { title: 'Generate Evidence', href: '/docs/intent/generate-compliance-evidence-from-scans' },
      { title: 'Gate Regressions', href: '/docs/intent/gate-on-drift-and-regressions' },
    ],
  },
  {
    title: 'Technical Foundations',
    href: '/docs/architecture',
    children: [
      { title: 'Docs Map', href: '/docs' },
      { title: 'Architecture', href: '/docs/architecture' },
      { title: 'Mental Model', href: '/docs/concepts/mental_model' },
      { title: 'Policy Authoring', href: '/docs/policy_authoring' },
      { title: 'Built-in Policy Rules', href: '/docs/policy_builtin_rules' },
      { title: 'Failure Taxonomy', href: '/docs/failure_taxonomy_exit_codes' },
      { title: 'Threat Model', href: '/docs/threat_model' },
    ],
  },
  {
    title: 'Trust and Contracts',
    href: '/docs/trust/deterministic-guarantees',
    children: [
      { title: 'Deterministic Guarantees', href: '/docs/trust/deterministic-guarantees' },
      { title: 'Coverage Matrix', href: '/docs/trust/detection-coverage-matrix' },
      { title: 'MCP Enrich Quality', href: '/docs/trust/mcp-enrich-quality-model' },
      { title: 'Proof Verification', href: '/docs/trust/proof-chain-verification' },
      { title: 'Contracts and Schemas', href: '/docs/trust/contracts-and-schemas' },
      { title: 'Compatibility Matrix', href: '/docs/contracts/compatibility_matrix' },
      { title: 'Security and Privacy', href: '/docs/trust/security-and-privacy' },
      { title: 'Release Integrity', href: '/docs/trust/release-integrity' },
      { title: 'Manifest Spec', href: '/docs/specs/wrkr-manifest' },
    ],
  },
  {
    title: 'Command Reference',
    href: '/docs/commands/index',
    children: [
      { title: 'index', href: '/docs/commands/index' },
      { title: 'root', href: '/docs/commands/root' },
      { title: 'scan', href: '/docs/commands/scan' },
      { title: 'mcp-list', href: '/docs/commands/mcp-list' },
      { title: 'inventory', href: '/docs/commands/inventory' },
      { title: 'report', href: '/docs/commands/report' },
      { title: 'score', href: '/docs/commands/score' },
      { title: 'verify', href: '/docs/commands/verify' },
      { title: 'evidence', href: '/docs/commands/evidence' },
      { title: 'regress', href: '/docs/commands/regress' },
      { title: 'fix', href: '/docs/commands/fix' },
    ],
  },
  {
    title: 'Positioning',
    href: '/docs/positioning',
    children: [
      { title: 'Positioning', href: '/docs/positioning' },
      { title: 'Evidence Templates', href: '/docs/evidence_templates' },
      { title: 'Personal Machine Hygiene', href: '/docs/examples/personal-hygiene' },
      { title: 'Security Team Workflow', href: '/docs/examples/security-team' },
      { title: 'Operator Playbooks', href: '/docs/examples/operator-playbooks' },
    ],
  },
  {
    title: 'Docs Hub',
    href: '/docs',
    children: [
      { title: 'Docs Home', href: '/docs' },
      { title: 'LLM Context', href: '/llms' },
      { title: 'llms.txt', href: '/llms.txt' },
      { title: 'llms-full.txt', href: '/llms-full.txt' },
      { title: 'AI Sitemap', href: '/ai-sitemap.xml' },
    ],
  },
];
