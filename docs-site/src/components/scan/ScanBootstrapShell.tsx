'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useState } from 'react';

import ScanStatusPanel from '@/components/scan/ScanStatusPanel';
import {
  DEMO_ORG,
  buildBootstrapRequest,
  buildDemoHref,
  buildActionWorkflow,
  buildCLICommand,
  isValidGitHubOrg,
  normalizeOrg,
  resolveBootstrapState,
  scanTargetOrg,
  type HandoffMode,
} from '@/lib/scan-bootstrap';

const STEP_COPY = [
  'Use this only when you explicitly want a secondary browser projection.',
  'Define the GitHub org and keep the handoff read-only.',
  'Trigger an existing Wrkr org scan contract through the CLI or GitHub Action.',
  'Paste the returned JSON and review the projected summary without creating dashboard state.',
];

export default function ScanBootstrapShell() {
  const searchParams = useSearchParams();
  const [orgInput, setOrgInput] = useState(searchParams.get('org') ?? DEMO_ORG);
  const [handoffMode, setHandoffMode] = useState<HandoffMode>('cli');
  const [artifactInput, setArtifactInput] = useState('');

  const normalizedOrg = normalizeOrg(orgInput);
  const org = scanTargetOrg(normalizedOrg);
  const hasInvalidOrg = !isValidGitHubOrg(normalizedOrg);
  const request = buildBootstrapRequest(org, handoffMode);
  const state = resolveBootstrapState(searchParams, { artifactText: artifactInput, org });

  return (
    <div className="not-prose space-y-8">
      <section className="overflow-hidden rounded-[2rem] border border-slate-700 bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.22),_rgba(15,23,42,0.94)_42%),linear-gradient(160deg,_rgba(15,23,42,0.96),_rgba(2,6,23,0.98))] p-8 shadow-[0_36px_120px_rgba(2,6,23,0.55)]">
        <div className="max-w-4xl">
          <p className="text-xs font-semibold uppercase tracking-[0.32em] text-cyan-200">Optional Thin Org Bootstrap</p>
          <h1 className="mt-4 text-4xl font-semibold leading-tight text-white lg:text-6xl">
            Use a read-only browser bootstrap only when the CLI path is not enough.
          </h1>
          <p className="mt-6 max-w-3xl text-base leading-8 text-slate-200">
            This page is a bootstrap shell, not a dashboard and not a hosted scan runtime. It exists for teams that want an
            optional browser projection of an existing Wrkr org scan after the Go CLI has already done the real work.
          </p>
          <div className="mt-8 flex flex-wrap gap-3 text-sm">
            <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-4 py-2 text-cyan-100">Read-only only</span>
            <span className="rounded-full border border-slate-600 bg-slate-900/70 px-4 py-2 text-slate-200">No runtime enforcement</span>
            <span className="rounded-full border border-slate-600 bg-slate-900/70 px-4 py-2 text-slate-200">Go CLI stays authoritative</span>
          </div>
        </div>
      </section>

      <section className="grid gap-5 lg:grid-cols-3">
        {STEP_COPY.map((copy, index) => (
          <div key={copy} className="rounded-[1.5rem] border border-slate-800 bg-slate-900/70 p-5">
            <p className="text-xs uppercase tracking-[0.24em] text-slate-500">step {index + 1}</p>
            <p className="mt-3 text-base leading-7 text-white">{copy}</p>
          </div>
        ))}
      </section>

      <section className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
        <div className="rounded-[1.75rem] border border-slate-800 bg-slate-900/70 p-6">
                <h2 className="text-2xl font-semibold text-white">Prepare the handoff</h2>
                <p className="mt-3 text-sm leading-7 text-slate-300">
            Start with the CLI/docs workflow unless you explicitly need this secondary projection surface. When GitHub Pages is
            serving the docs site statically, the request below stays read-only and only projects returned JSON.
                </p>

          <label className="mt-6 block">
            <span className="text-xs uppercase tracking-[0.2em] text-slate-500">GitHub org</span>
            <input
              value={orgInput}
              onChange={(event) => setOrgInput(event.target.value)}
              className="mt-2 w-full rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400"
              placeholder={DEMO_ORG}
            />
          </label>
          {hasInvalidOrg ? (
            <p className="mt-3 rounded-xl border border-amber-400/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
              GitHub org values must use letters, numbers, and internal hyphens only. The generated handoff uses `{org}` until the input is valid.
            </p>
          ) : null}

          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              onClick={() => setHandoffMode('cli')}
              className={`rounded-2xl border px-4 py-4 text-left transition ${
                handoffMode === 'cli'
                  ? 'border-cyan-400 bg-cyan-500/10 text-cyan-100'
                  : 'border-slate-700 bg-slate-950 text-slate-200 hover:border-slate-500'
              }`}
            >
              <span className="block text-xs uppercase tracking-[0.2em]">CLI handoff</span>
                  <span className="mt-2 block text-sm">Run `wrkr scan --github-org` locally or in CI, then paste the returned JSON here.</span>
            </button>
            <button
              type="button"
              onClick={() => setHandoffMode('github_action')}
              className={`rounded-2xl border px-4 py-4 text-left transition ${
                handoffMode === 'github_action'
                  ? 'border-cyan-400 bg-cyan-500/10 text-cyan-100'
                  : 'border-slate-700 bg-slate-950 text-slate-200 hover:border-slate-500'
              }`}
            >
              <span className="block text-xs uppercase tracking-[0.2em]">GitHub Action handoff</span>
                  <span className="mt-2 block text-sm">Use the existing Wrkr Action contract when you need an optional workflow-dispatched handoff.</span>
            </button>
          </div>

          <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
            <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Bootstrap request</p>
            <pre className="mt-4 !m-0 !border-0 !bg-transparent">
              <code>{JSON.stringify(request, null, 2)}</code>
            </pre>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-[1.75rem] border border-slate-800 bg-slate-900/70 p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-2xl font-semibold text-white">Trigger the existing Wrkr contract</h2>
                <p className="mt-2 text-sm leading-7 text-slate-300">
                  The CLI remains the source of truth. The GitHub Action snippet is a thin wrapper over the same target contract, not a different product path.
                </p>
              </div>
              <Link href="/docs/commands/scan" className="rounded-full border border-slate-700 px-4 py-2 text-sm text-slate-200 hover:border-cyan-400 hover:text-cyan-100">
                Scan contract
              </Link>
            </div>

            <div className="mt-6 grid gap-4">
              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.24em] text-slate-500">CLI</p>
                <pre className="mt-4 !m-0 !border-0 !bg-transparent">
                  <code>{buildCLICommand(org)}</code>
                </pre>
              </div>
              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.24em] text-slate-500">GitHub Action</p>
                <pre className="mt-4 !m-0 !border-0 !bg-transparent">
                  <code>{buildActionWorkflow(org)}</code>
                </pre>
              </div>
            </div>

            <div className="mt-6 flex flex-wrap gap-3 text-sm">
              <Link href={buildDemoHref(org, 'success')} className="rounded-full border border-emerald-400/40 bg-emerald-500/10 px-4 py-2 text-emerald-100 hover:border-emerald-300">
                Load optional example
              </Link>
              <Link href={buildDemoHref(org, 'denied')} className="rounded-full border border-amber-400/40 bg-amber-500/10 px-4 py-2 text-amber-100 hover:border-amber-300">
                Demo denied auth
              </Link>
              <Link href={buildDemoHref(org, 'missing_state')} className="rounded-full border border-amber-400/40 bg-amber-500/10 px-4 py-2 text-amber-100 hover:border-amber-300">
                Demo missing state
              </Link>
              <Link href={buildDemoHref(org, 'backend_unavailable')} className="rounded-full border border-amber-400/40 bg-amber-500/10 px-4 py-2 text-amber-100 hover:border-amber-300">
                Demo unavailable backend
              </Link>
              <Link href={`/scan?org=${encodeURIComponent(org)}`} className="rounded-full border border-slate-700 px-4 py-2 text-slate-200 hover:border-slate-500">
                Reset shell
              </Link>
            </div>
          </div>

          <div className="rounded-[1.75rem] border border-slate-800 bg-slate-900/70 p-6">
            <h2 className="text-2xl font-semibold text-white">Paste returned JSON</h2>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              Paste `wrkr scan --github-org ... --json` output here only when you want a browser summary. The browser never
              replaces the original scan state and never runs the scan itself.
            </p>
            <textarea
              value={artifactInput}
              onChange={(event) => setArtifactInput(event.target.value)}
              className="mt-4 min-h-[15rem] w-full rounded-[1.5rem] border border-slate-700 bg-slate-950 px-4 py-4 font-mono text-sm text-slate-100 outline-none transition focus:border-cyan-400"
              placeholder='{"status":"ok","target":{"mode":"org","value":"acme"},"posture_score":{"score":71}}'
            />
          </div>
        </div>
      </section>

      <ScanStatusPanel state={state} />

      <section className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-[1.5rem] border border-slate-800 bg-slate-900/70 p-6">
          <h2 className="text-2xl font-semibold text-white">Boundaries</h2>
          <ul className="mt-4 space-y-3 text-sm leading-7 text-slate-300">
            <li>The web shell does not run detectors, score risk, sign proof, or persist scan state.</li>
            <li>Privacy copy is explicit: only paste machine-readable Wrkr output that you intend to review in the browser.</li>
            <li>When a handoff fails, the shell stays deterministic and surfaces denied access, missing callback state, or unavailable backend states.</li>
          </ul>
        </div>
        <div className="rounded-[1.5rem] border border-slate-800 bg-slate-900/70 p-6">
          <h2 className="text-2xl font-semibold text-white">Continue in Wrkr</h2>
          <div className="mt-4 flex flex-wrap gap-3 text-sm">
            <Link href="/docs/examples/security-team" className="rounded-full border border-slate-700 px-4 py-2 text-slate-100 hover:border-cyan-400 hover:text-cyan-100">
              Security workflow
            </Link>
            <Link href="/docs/positioning" className="rounded-full border border-slate-700 px-4 py-2 text-slate-100 hover:border-cyan-400 hover:text-cyan-100">
              Product boundaries
            </Link>
            <Link href="/docs/commands/report" className="rounded-full border border-slate-700 px-4 py-2 text-slate-100 hover:border-cyan-400 hover:text-cyan-100">
              Report JSON
            </Link>
            <Link href="/docs/commands/evidence" className="rounded-full border border-slate-700 px-4 py-2 text-slate-100 hover:border-cyan-400 hover:text-cyan-100">
              Evidence
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
