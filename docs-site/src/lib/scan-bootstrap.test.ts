import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DEMO_SCAN_PAYLOAD,
  buildBootstrapRequest,
  buildCLICommand,
  buildDemoHref,
  isValidGitHubOrg,
  projectSummaryArtifact,
  resolveBootstrapState,
  scanTargetOrg,
} from './scan-bootstrap';

test('buildBootstrapRequest returns a versioned read-only contract', () => {
  const request = buildBootstrapRequest('acme', 'cli');
  assert.equal(request.schema_id, 'wrkr.web.bootstrap_request');
  assert.equal(request.schema_version, '1.0.0');
  assert.equal(request.target.mode, 'github_org');
  assert.equal(request.target.value, 'acme');
  assert.deepEqual(request.target.required_scopes, ['metadata:read', 'contents:read']);
  assert.equal(request.handoff.mode, 'cli');
  assert.match(request.handoff.cli_command, /wrkr scan --github-org acme --github-api https:\/\/api\.github\.com --json/);
});

test('buildCLICommand and demo links stay deterministic', () => {
  assert.equal(buildCLICommand('acme'), 'wrkr scan --github-org acme --github-api https://api.github.com --json');
  assert.equal(buildDemoHref('acme', 'success'), '/scan?org=acme&demo=success');
  assert.equal(buildDemoHref('acme', 'denied'), '/scan?org=acme&error=denied');
});

test('invalid org values do not flow into generated handoff snippets', () => {
  assert.equal(isValidGitHubOrg('acme-platform'), true);
  assert.equal(isValidGitHubOrg('acme; rm -rf /'), false);
  assert.equal(scanTargetOrg('acme; rm -rf /'), 'acme');
  assert.equal(buildCLICommand('acme; rm -rf /'), 'wrkr scan --github-org acme --github-api https://api.github.com --json');
  assert.equal(buildDemoHref('acme; rm -rf /', 'success'), '/scan?org=acme&demo=success');
});

test('projectSummaryArtifact accepts Wrkr org scan JSON', () => {
  const projected = projectSummaryArtifact(JSON.stringify(DEMO_SCAN_PAYLOAD), 'acme');
  assert.equal(projected.ok, true);
  if (!projected.ok) {
    return;
  }
  assert.equal(projected.artifact.source_contract, 'wrkr scan --github-org --json');
  assert.equal(projected.artifact.org, 'acme');
  assert.equal(projected.artifact.repo_count, 3);
  assert.equal(projected.artifact.top_findings.length, 3);
});

test('resolveBootstrapState maps denied auth, missing state, and backend unavailable failures', () => {
  const denied = resolveBootstrapState({ error: 'denied', org: 'acme' });
  assert.equal(denied.kind, 'auth_denied');

  const missingState = resolveBootstrapState({ error: 'missing_state', org: 'acme' });
  assert.equal(missingState.kind, 'missing_state');

  const backendUnavailable = resolveBootstrapState({ error: 'backend_unavailable', org: 'acme' });
  assert.equal(backendUnavailable.kind, 'backend_unavailable');
});

test('resolveBootstrapState projects the example success artifact when requested', () => {
  const ready = resolveBootstrapState({ demo: 'success', org: 'acme' });
  assert.equal(ready.kind, 'ready');
  if (ready.kind !== 'ready') {
    return;
  }
  assert.equal(ready.artifact.org, 'acme');
  assert.equal(ready.artifact.top_findings[0]?.severity, 'high');
});

test('resolveBootstrapState rejects invalid artifact input', () => {
  const invalid = resolveBootstrapState({}, { artifactText: '{"status":"ok"}', org: 'acme' });
  assert.equal(invalid.kind, 'invalid_artifact');
  assert.match(invalid.message, /Expected a Wrkr org scan JSON payload/);
});
