import type { Metadata } from 'next';
import Link from 'next/link';
import { canonicalUrl } from '@/lib/site';

export const metadata: Metadata = {
  title: 'LLM Context | Wrkr',
  description: 'Machine-readable and human-readable context for assistants and evaluators about Wrkr OSS.',
  alternates: { canonical: canonicalUrl('/llms/') },
};

const resources = [
  { label: 'llms.txt', href: '/llms.txt' },
  { label: 'llms-full.txt (Extended)', href: '/llms-full.txt' },
  { label: 'LLM Product Overview', href: '/llm/product.md' },
  { label: 'LLM Quickstart', href: '/llm/quickstart.md' },
  { label: 'LLM Security and Privacy', href: '/llm/security.md' },
  { label: 'LLM Contracts', href: '/llm/contracts.md' },
  { label: 'LLM FAQ', href: '/llm/faq.md' },
  { label: 'Crawler Policy (robots.txt)', href: '/robots.txt' },
  { label: 'AI Sitemap', href: '/ai-sitemap.xml' },
];

export default function LlmsPage() {
  return (
    <div className="not-prose">
      <h1 className="text-3xl lg:text-4xl font-bold text-white mb-4">LLM Context</h1>
      <p className="text-gray-400 max-w-3xl mb-8">
        These resources are optimized for AI assistants, search agents, and evaluators to discover Wrkr capabilities,
        contracts, and safe usage boundaries.
      </p>
      <div className="space-y-3">
        {resources.map((resource) => (
          <Link
            key={resource.href}
            href={resource.href}
            className="block rounded-lg border border-gray-700 bg-gray-900/40 px-4 py-3 text-gray-200 hover:bg-gray-800/50"
          >
            {resource.label}
          </Link>
        ))}
      </div>
      <div className="mt-10">
        <Link href="/docs" className="text-cyan-300 hover:text-cyan-200">
          Back to docs
        </Link>
      </div>
    </div>
  );
}
