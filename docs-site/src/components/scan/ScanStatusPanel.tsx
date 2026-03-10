import React from 'react';

import type { BootstrapState } from '@/lib/scan-bootstrap';

function badgeClass(kind: BootstrapState['kind']): string {
  if (kind === 'ready') {
    return 'border-emerald-400/40 bg-emerald-500/10 text-emerald-200';
  }
  if (kind === 'idle') {
    return 'border-sky-400/40 bg-sky-500/10 text-sky-200';
  }
  return 'border-amber-400/40 bg-amber-500/10 text-amber-100';
}

export default function ScanStatusPanel({ state }: { state: BootstrapState }) {
  return (
    <section className="rounded-[1.5rem] border border-slate-700 bg-slate-950/80 p-6 shadow-[0_24px_80px_rgba(2,6,23,0.45)]">
      <div className="mb-5 flex items-center gap-3">
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] ${badgeClass(state.kind)}`}>
          {state.kind.replace('_', ' ')}
        </span>
        <span className="text-xs uppercase tracking-[0.24em] text-slate-500">read-only shell</span>
      </div>

      <h2 className="text-2xl font-semibold text-white">{state.title}</h2>
      <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">{state.message}</p>
      <p className="mt-3 rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-sm text-slate-200">
        Next step: {state.next_step}
      </p>

      {state.kind === 'ready' ? (
        <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
            <p className="text-xs uppercase tracking-[0.24em] text-slate-500">summary artifact</p>
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">org</p>
                <p className="mt-2 text-lg font-semibold text-white">{state.artifact.org}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">posture score</p>
                <p className="mt-2 text-lg font-semibold text-white">{state.artifact.posture_score.toFixed(0)}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">repo count</p>
                <p className="mt-2 text-lg font-semibold text-white">{state.artifact.repo_count}</p>
              </div>
            </div>
            <p className="mt-5 text-sm text-slate-300">{state.artifact.summary}</p>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5">
            <p className="text-xs uppercase tracking-[0.24em] text-slate-500">top findings</p>
            <div className="mt-4 space-y-3">
              {state.artifact.top_findings.length > 0 ? (
                state.artifact.top_findings.map((finding) => (
                  <div key={`${finding.location}-${finding.summary}`} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-medium uppercase tracking-[0.12em] text-amber-200">{finding.severity}</span>
                      <span className="text-sm text-slate-300">{finding.risk_score.toFixed(1)}</span>
                    </div>
                    <p className="mt-2 text-sm text-white">{finding.summary}</p>
                    <p className="mt-2 text-xs text-slate-500">{finding.location}</p>
                  </div>
                ))
              ) : (
                <p className="text-sm text-slate-300">No ranked findings were included in the supplied summary artifact.</p>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
