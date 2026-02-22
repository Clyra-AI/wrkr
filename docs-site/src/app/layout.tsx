import type { Metadata } from 'next';
import './globals.css';
import Sidebar from '@/components/Sidebar';
import Header from '@/components/Header';
import { SITE_BASE_PATH, SITE_ORIGIN } from '@/lib/site';

export const metadata: Metadata = {
  metadataBase: new URL(`${SITE_ORIGIN}${SITE_BASE_PATH}`),
  title: 'Wrkr | AI-DSPM Discovery with Deterministic Proof',
  description:
    'Wrkr evaluates AI dev tool configurations across GitHub repos/orgs against policy. Posture-scored, compliance-ready, deterministic by default.',
  keywords:
    'AI-DSPM, ai governance, ai tooling inventory, mcp risk, headless agent risk, deterministic evidence, compliance evidence, ai posture scoring',
  openGraph: {
    title: 'Wrkr | AI-DSPM Discovery with Deterministic Proof',
    description:
      'Deterministic discovery and risk scoring for AI development tooling with compliance-ready evidence outputs.',
    url: 'https://clyra-ai.github.io/wrkr',
    siteName: 'Wrkr',
    type: 'website',
    images: [
      {
        url: '/og.svg',
        width: 1200,
        height: 630,
        alt: 'Wrkr',
      },
    ],
  },
  icons: {
    icon: [
      { url: `${SITE_BASE_PATH}/favicon.svg`, type: 'image/svg+xml' },
      { url: `${SITE_BASE_PATH}/favicon.ico`, type: 'image/x-icon' },
    ],
    shortcut: `${SITE_BASE_PATH}/favicon.ico`,
    apple: `${SITE_BASE_PATH}/favicon.svg`,
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Wrkr | AI-DSPM Discovery with Deterministic Proof',
    description:
      'Evaluate AI dev tool configurations across GitHub repo/org against policy. Posture-scored, compliance-ready.',
    images: ['/og.svg'],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">
        <Header />
        <div className="flex max-w-7xl mx-auto px-4 lg:px-8">
          <Sidebar />
          <main className="flex-1 min-w-0 py-8 lg:pl-8">
            <article className="prose prose-invert max-w-none">{children}</article>
          </main>
        </div>
      </body>
    </html>
  );
}
