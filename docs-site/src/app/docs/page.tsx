import Link from 'next/link';
import type { Metadata } from 'next';
import { canonicalUrl } from '@/lib/site';

export const metadata: Metadata = {
  title: 'Wrkr Documentation',
  description: 'Command-first, deterministic documentation for Wrkr AI-DSPM workflows.',
  alternates: { canonical: canonicalUrl('/docs/') },
};

const tracks = [
  {
    title: 'Track 1: First Deterministic Scan',
    steps: [
      { label: 'Adopt In One PR', href: '/docs/adopt_in_one_pr' },
      { label: 'Quickstart', href: '/docs/examples/quickstart' },
      { label: 'Integration Checklist', href: '/docs/integration_checklist' },
      { label: 'Command Index', href: '/docs/commands/index' },
      { label: 'Scan Command', href: '/docs/commands/scan' },
    ],
  },
  {
    title: 'Track 2: High-Intent Workflows',
    steps: [
      { label: 'Scan Org Repos', href: '/docs/intent/scan-org-repos-for-ai-agents-configs' },
      { label: 'Detect Headless Risk', href: '/docs/intent/detect-headless-agent-risk' },
      { label: 'Generate Evidence', href: '/docs/intent/generate-compliance-evidence-from-scans' },
      { label: 'Gate Regressions', href: '/docs/intent/gate-on-drift-and-regressions' },
    ],
  },
  {
    title: 'Track 3: Technical Foundations',
    steps: [
      { label: 'Architecture', href: '/docs/architecture' },
      { label: 'Mental Model', href: '/docs/concepts/mental_model' },
      { label: 'Policy Authoring', href: '/docs/policy_authoring' },
      { label: 'Failure Taxonomy', href: '/docs/failure_taxonomy_exit_codes' },
      { label: 'Threat Model', href: '/docs/threat_model' },
    ],
  },
  {
    title: 'Track 4: Proof and Contracts',
    steps: [
      { label: 'Verify Command', href: '/docs/commands/verify' },
      { label: 'Evidence Command', href: '/docs/commands/evidence' },
      { label: 'Manifest Spec', href: '/docs/specs/wrkr-manifest' },
      { label: 'Compatibility Matrix', href: '/docs/contracts/compatibility_matrix' },
      { label: 'Proof Verification', href: '/docs/trust/proof-chain-verification' },
      { label: 'Contracts and Schemas', href: '/docs/trust/contracts-and-schemas' },
    ],
  },
  {
    title: 'Track 5: Positioning and Packaging',
    steps: [
      { label: 'Positioning', href: '/docs/positioning' },
      { label: 'Evidence Templates', href: '/docs/evidence_templates' },
      { label: 'FAQ', href: '/docs/faq' },
      { label: 'Deterministic Guarantees', href: '/docs/trust/deterministic-guarantees' },
      { label: 'Coverage Matrix', href: '/docs/trust/detection-coverage-matrix' },
      { label: 'Security and Privacy', href: '/docs/trust/security-and-privacy' },
      { label: 'Release Integrity', href: '/docs/trust/release-integrity' },
    ],
  },
  {
    title: 'Track 6: Hub and Discovery',
    steps: [
      { label: 'LLM Context', href: '/llms' },
      { label: 'llms.txt', href: '/llms.txt' },
      { label: 'llms-full.txt', href: '/llms-full.txt' },
      { label: 'AI Sitemap', href: '/ai-sitemap.xml' },
      { label: 'Crawler Policy', href: '/robots.txt' },
    ],
  },
];

export default function DocsHomePage() {
  return (
    <div className="not-prose">
      <h1 className="text-3xl lg:text-4xl font-bold text-white mb-4">Documentation</h1>
      <p className="text-gray-400 mb-10 max-w-3xl">
        Command-first references and intent guides for deterministic AI tooling posture workflows.
      </p>

      <div className="grid gap-6">
        {tracks.map((track) => (
          <section key={track.title} className="rounded-xl border border-gray-700 bg-gray-900/30 p-6">
            <h2 className="text-xl font-semibold text-white mb-4">{track.title}</h2>
            <div className="flex flex-wrap gap-3">
              {track.steps.map((step) => (
                <Link
                  key={step.href}
                  href={step.href}
                  className="inline-flex items-center rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-200 hover:bg-gray-800/70"
                >
                  {step.label}
                </Link>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
