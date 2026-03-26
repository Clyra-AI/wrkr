import Link from 'next/link';
import type { Metadata } from 'next';
import { canonicalUrl } from '@/lib/site';

export const metadata: Metadata = {
  title: 'Wrkr | Know Your AI Tooling Posture',
  description:
    'Know what AI tools, agents, and MCP servers are configured in your org before they become unreviewed access, with deterministic repo-local and local-machine fallback paths when hosted setup is not ready yet.',
  alternates: {
    canonical: canonicalUrl('/'),
  },
};

const QUICKSTART = `# Evaluator-safe first pass: use the curated scenario
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/wrkr-scenario-evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --json

# Security and platform teams: widen to org posture next
# Hosted prerequisites: set --github-api and usually a GitHub token for private repos or rate limits
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json

# If hosted prerequisites are not ready yet after the scenario run, use a deterministic fallback
wrkr scan --path ./your-repo --json

# Developers: use the secondary local-machine hygiene path
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json`;

const features = [
  {
    title: 'Org Evidence',
    description: 'Widen from local hygiene to GitHub org posture and emit deterministic evidence bundles for audit and CI.',
    href: '/docs/examples/security-team',
  },
  {
    title: 'MCP Posture',
    description: 'Project MCP server transport, requested permissions, gateway posture, and trust overlay from saved state.',
    href: '/docs/commands/mcp-list',
  },
  {
    title: 'Workflow Drift Review',
    description: 'Use inventory drift for day-to-day review and regress gates when you need policy-grade change detection.',
    href: '/docs/commands/regress',
  },
  {
    title: 'Local Setup Inventory',
    description: 'Use the secondary local-machine path to inspect supported AI configs, project markers, and secret-presence signals.',
    href: '/docs/examples/personal-hygiene',
  },
  {
    title: 'Command Contracts',
    description: 'Keep automation grounded on stable `--json`, SARIF, and exit-code surfaces rather than ad hoc scraping.',
    href: '/docs/commands/index',
  },
  {
    title: 'Scope Boundaries',
    description: 'Wrkr inventories what is configured and what it can touch. It does not replace vulnerability scanners or runtime control.',
    href: '/docs/positioning',
  },
  {
    title: 'Optional Browser Bootstrap',
    description: 'Use the read-only browser handoff only when you explicitly want a secondary org-scan projection surface.',
    href: '/scan',
  },
];

const faqs = [
  {
    question: 'What is Wrkr in one sentence?',
    answer: 'Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps a deterministic local-machine hygiene path available for developers.',
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
    answer: 'Use `wrkr regress run` in CI. It accepts a saved regress baseline or a raw saved scan snapshot baseline. Exit code `5` indicates drift.',
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
    'Wrkr inventories AI tools, agents, and MCP servers across local setup, repos, and GitHub orgs with deterministic posture and evidence outputs.',
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
          Know Your AI Tooling
          <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent"> Before It Becomes Unreviewed Access.</span>
        </h1>
        <p className="text-xl text-gray-400 max-w-3xl mx-auto mb-4">
          Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps a deterministic local-machine hygiene path available for developers.
        </p>
        <p className="text-base text-gray-500 max-w-3xl mx-auto mb-8">
          Discover supported AI dev tools, MCP servers, and agent frameworks, map what they can touch, show what changed, and emit proof artifacts for audits and CI. Start with the curated scenario when you want the evaluator-safe path, then widen to org posture when hosted prerequisites are ready; use repo-local or local-machine fallback paths when you need zero-integration first value and want to avoid repo-root fixture noise in the Wrkr repo itself.
        </p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link href="/docs/examples/security-team" className="px-6 py-3 bg-emerald-400 hover:bg-emerald-300 text-gray-950 font-semibold rounded-lg transition-colors">
            Security Team Flow
          </Link>
          <Link href="/docs/examples/quickstart" className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-gray-900 font-semibold rounded-lg transition-colors">
            Start Here
          </Link>
          <Link href="/scan" className="px-6 py-3 bg-gray-800 hover:bg-gray-700 text-gray-100 font-semibold rounded-lg border border-gray-700 transition-colors">
            Optional Browser Bootstrap
          </Link>
        </div>
        <p className="text-sm text-gray-500 mt-5">
          Homebrew, pinned Go install, optional secondary `@latest`, and `wrkr version --json` verification live in{' '}
          <Link href="/docs/start-here#install" className="text-cyan-300 hover:text-cyan-200">
            Start Here install
          </Link>
          {' '}and the optional secondary browser handoff lives at{' '}
          <Link href="/scan" className="text-emerald-300 hover:text-emerald-200">
            /scan
          </Link>
          .
        </p>
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
              <td className="py-3 px-4 text-gray-300">deterministic machine, repo, and org inventory</td>
            </tr>
            <tr>
              <td className="py-3 px-4 text-gray-300 font-medium">MCP trust posture</td>
              <td className="py-3 px-4 text-gray-500">partial config knowledge, no privilege map</td>
              <td className="py-3 px-4 text-gray-300">transport, permissions, gateway, and trust context</td>
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
        <h2 className="text-2xl font-bold text-white mb-4">Start with your machine. Widen to your org only when you need posture and proof.</h2>
        <p className="text-gray-400 mb-6">Use command-first docs that developers, security teams, and assistants can all validate against the same deterministic CLI outputs.</p>
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
