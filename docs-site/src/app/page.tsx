import Link from 'next/link';
import type { Metadata } from 'next';
import { canonicalUrl } from '@/lib/site';

export const metadata: Metadata = {
  title: 'Wrkr | AI-DSPM Discovery with Deterministic Proof',
  description:
    'Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.',
  alternates: {
    canonical: canonicalUrl('/'),
  },
};

const QUICKSTART = `# Initialize with deterministic defaults
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json

# Run scan and posture outputs
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --json
wrkr report --top 5 --json
wrkr score --json

# Generate and verify compliance evidence
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
wrkr verify --chain --json

# Gate on drift
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json`;

const features = [
  {
    title: 'Org and Repo Discovery',
    description: 'Discover AI tooling declarations across repo/org/path sources with deterministic output contracts.',
    href: '/docs/intent/scan-org-repos-for-ai-agents-configs',
  },
  {
    title: 'Headless Risk Ranking',
    description: 'Surface high-impact CI/autonomous execution risks with ranked, explainable findings.',
    href: '/docs/intent/detect-headless-agent-risk',
  },
  {
    title: 'Compliance Evidence',
    description: 'Generate framework-mapped evidence bundles and verify proof chain integrity.',
    href: '/docs/intent/generate-compliance-evidence-from-scans',
  },
  {
    title: 'Deterministic Regressions',
    description: 'Create baseline posture gates and fail CI with stable drift reasons.',
    href: '/docs/intent/gate-on-drift-and-regressions',
  },
  {
    title: 'Open Manifest Contract',
    description: 'Use `wrkr-manifest.yaml` as a portable policy and lifecycle posture contract.',
    href: '/docs/specs/wrkr-manifest',
  },
  {
    title: 'Agent-Readable Context',
    description: 'LLM-oriented docs resources, AI sitemap, and crawler policy for reliable assistant grounding.',
    href: '/llms',
  },
];

const faqs = [
  {
    question: 'What is Wrkr in one sentence?',
    answer: 'Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.',
  },
  {
    question: 'Does Wrkr require a hosted control plane?',
    answer: 'No. Wrkr is deterministic and file-based by default, with local scan state and local evidence generation.',
  },
  {
    question: 'What makes Wrkr outputs audit-friendly?',
    answer: 'Wrkr emits deterministic JSON contracts, stable exit codes, and proof-chain verifiable evidence paths.',
  },
  {
    question: 'Can Wrkr enforce runtime side effects?',
    answer: 'Wrkr is a discovery and posture layer. Runtime side-effect enforcement belongs to control-plane runtimes like Gait.',
  },
  {
    question: 'How do I fail CI on posture drift?',
    answer: 'Use `wrkr regress init` to create a baseline and `wrkr regress run` in CI. Exit code `5` indicates drift.',
  },
  {
    question: 'How do I generate compliance evidence?',
    answer: 'Run `wrkr evidence --frameworks ... --json` and validate integrity with `wrkr verify --chain --json`.',
  },
];

const softwareApplicationJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'Wrkr',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Linux, macOS, Windows',
  description:
    'Wrkr evaluates AI dev tool configurations across GitHub repo/org against policy with deterministic posture scoring and compliance-ready evidence.',
  url: 'https://clyra-ai.github.io/wrkr/',
  softwareHelp: 'https://clyra-ai.github.io/wrkr/docs/',
  codeRepository: 'https://github.com/Clyra-AI/wrkr',
  offers: {
    '@type': 'Offer',
    price: '0',
    priceCurrency: 'USD',
  },
};

const faqJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: faqs.map((entry) => ({
    '@type': 'Question',
    name: entry.question,
    acceptedAnswer: {
      '@type': 'Answer',
      text: entry.answer,
    },
  })),
};

export default function HomePage() {
  return (
    <div className="not-prose">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareApplicationJsonLd) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }} />

      <div className="text-center py-12 lg:py-20">
        <h1 className="text-4xl lg:text-6xl font-bold text-white mb-6">
          Evaluate AI Tooling Posture.
          <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent"> Prove It Deterministically.</span>
        </h1>
        <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-4">
          Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.
        </p>
        <p className="text-base text-gray-500 max-w-3xl mx-auto mb-8">
          Scan, rank, regress, verify, and export evidence with stable `--json` outputs and fail-closed safety defaults.
        </p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link href="/docs/examples/quickstart" className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-gray-900 font-semibold rounded-lg transition-colors">
            Start Here
          </Link>
          <Link href="/docs/intent/scan-org-repos-for-ai-agents-configs" className="px-6 py-3 bg-gray-800 hover:bg-gray-700 text-gray-100 font-semibold rounded-lg border border-gray-700 transition-colors">
            Org Scan Flow
          </Link>
        </div>
      </div>

      <div className="max-w-3xl mx-auto mb-16">
        <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-4 overflow-x-auto">
          <pre><code className="text-cyan-300 text-sm">{QUICKSTART}</code></pre>
        </div>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-16">
        {features.map((feature) => (
          <Link
            key={feature.title}
            href={feature.href}
            className="block p-6 bg-gray-800/30 hover:bg-gray-800/50 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors"
          >
            <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
            <p className="text-sm text-gray-400">{feature.description}</p>
          </Link>
        ))}
      </div>

      <div className="mb-16 overflow-x-auto">
        <h2 className="text-2xl font-bold text-white mb-6 text-center">Why Teams Use Wrkr</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left py-3 px-4 text-gray-400"></th>
              <th className="text-left py-3 px-4 text-gray-400">Without Wrkr</th>
              <th className="text-left py-3 px-4 text-cyan-400">With Wrkr</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            <tr>
              <td className="py-3 px-4 text-gray-300 font-medium">AI tool inventory</td>
              <td className="py-3 px-4 text-gray-500">manual surveys, stale answers</td>
              <td className="py-3 px-4 text-gray-300">deterministic repo/org inventory</td>
            </tr>
            <tr>
              <td className="py-3 px-4 text-gray-300 font-medium">Headless risk visibility</td>
              <td className="py-3 px-4 text-gray-500">ad-hoc grep and assumptions</td>
              <td className="py-3 px-4 text-gray-300">ranked findings with posture context</td>
            </tr>
            <tr>
              <td className="py-3 px-4 text-gray-300 font-medium">Compliance evidence</td>
              <td className="py-3 px-4 text-gray-500">manual artifact assembly</td>
              <td className="py-3 px-4 text-gray-300">command-generated evidence bundle</td>
            </tr>
            <tr>
              <td className="py-3 px-4 text-gray-300 font-medium">Regression gating</td>
              <td className="py-3 px-4 text-gray-500">no baseline contract</td>
              <td className="py-3 px-4 text-gray-300">stable drift reasons and exit code 5</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="mb-16">
        <h2 className="text-2xl font-bold text-white mb-6 text-center">Frequently Asked Questions</h2>
        <div className="grid md:grid-cols-2 gap-4">
          {faqs.map((entry) => (
            <div key={entry.question} className="rounded-lg border border-gray-700 bg-gray-900/40 p-5">
              <h3 className="text-base font-semibold text-gray-100 mb-2">{entry.question}</h3>
              <p className="text-sm text-gray-300">{entry.answer}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="text-center py-12 border-t border-gray-800">
        <h2 className="text-2xl font-bold text-white mb-4">Use command-first docs that agents can quote and operators can verify.</h2>
        <p className="text-gray-400 mb-6">Start with intent guides, then validate with deterministic CLI outputs.</p>
        <Link href="/docs" className="inline-block px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-gray-900 font-semibold rounded-lg transition-colors">
          Open Documentation
        </Link>
        <p className="text-sm text-gray-500 mt-5">
          For assistant and crawler discovery resources, use{' '}
          <Link href="/llms" className="text-cyan-300 hover:text-cyan-200">
            LLM Context
          </Link>
          .
        </p>
      </div>
    </div>
  );
}
