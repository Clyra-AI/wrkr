import assert from 'node:assert/strict';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import ScanStatusPanel from './ScanStatusPanel';

test('ScanStatusPanel renders ready artifact details', () => {
  const html = renderToStaticMarkup(
    <ScanStatusPanel
      state={{
        kind: 'ready',
        title: 'Projected Wrkr summary artifact',
        message: 'Projected from the Wrkr org scan contract.',
        next_step: 'Continue with report and evidence commands.',
        artifact: {
          schema_id: 'wrkr.web.scan_summary',
          schema_version: '1.0.0',
          source_contract: 'wrkr scan --github-org --json',
          org: 'acme',
          status: 'ok',
          posture_score: 71,
          repo_count: 3,
          top_findings: [
            {
              severity: 'high',
              summary: 'Headless workflow writes to production.',
              location: '.github/workflows/deploy.yml',
              risk_score: 9.6,
            },
          ],
          summary: 'Projected 1 top finding from the Wrkr org scan contract.',
        },
      }}
    />,
  );

  assert.match(html, /Projected Wrkr summary artifact/);
  assert.match(html, /acme/);
  assert.match(html, /Headless workflow writes to production\./);
});

test('ScanStatusPanel renders failure guidance', () => {
  const html = renderToStaticMarkup(
    <ScanStatusPanel
      state={{
        kind: 'backend_unavailable',
        title: 'The scan handoff endpoint was unavailable',
        message: 'Wrkr did not receive a summary artifact from the handoff target.',
        next_step: 'Run the CLI command directly and paste the returned JSON.',
      }}
    />,
  );

  assert.match(html, /endpoint was unavailable/);
  assert.match(html, /Run the CLI command directly/);
});
