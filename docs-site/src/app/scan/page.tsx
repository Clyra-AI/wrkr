import type { Metadata } from 'next';
import { Suspense } from 'react';

import ScanBootstrapShell from '@/components/scan/ScanBootstrapShell';
import { canonicalUrl } from '@/lib/site';

export const metadata: Metadata = {
  title: 'Wrkr Web Bootstrap',
  description:
    'Read-only bootstrap shell for Wrkr org scans. Prepare a handoff, trigger the existing Wrkr contract, and project the returned summary artifact.',
  alternates: {
    canonical: canonicalUrl('/scan/'),
  },
};

function ScanBootstrapFallback() {
  return (
    <div className="not-prose rounded-[1.5rem] border border-slate-800 bg-slate-900/70 p-6">
      <p className="text-sm uppercase tracking-[0.24em] text-slate-500">loading bootstrap shell</p>
      <p className="mt-4 text-base text-slate-200">Preparing the read-only handoff view.</p>
    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={<ScanBootstrapFallback />}>
      <ScanBootstrapShell />
    </Suspense>
  );
}
