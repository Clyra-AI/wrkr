export type HandoffMode = 'cli' | 'github_action';

export interface BootstrapRequest {
  schema_id: 'wrkr.web.bootstrap_request';
  schema_version: '1.0.0';
  transport: 'equivalent_handoff';
  target: {
    mode: 'github_org';
    value: string;
    read_only: true;
    required_scopes: string[];
  };
  handoff: {
    mode: HandoffMode;
    cli_command: string;
    github_action_workflow: string;
    return_contract: 'wrkr.web.scan_summary';
    return_schema_version: '1.0.0';
  };
  boundaries: string[];
}

export interface WebSummaryFinding {
  severity: string;
  summary: string;
  location: string;
  risk_score: number;
}

export interface WebScanSummaryArtifact {
  schema_id: 'wrkr.web.scan_summary';
  schema_version: '1.0.0';
  source_contract: 'wrkr scan --github-org --json' | 'wrkr action scheduled summary' | 'wrkr.web.scan_summary';
  org: string;
  status: string;
  posture_score: number;
  repo_count: number;
  top_findings: WebSummaryFinding[];
  summary: string;
}

export type BootstrapState =
  | {
      kind: 'idle';
      title: string;
      message: string;
      next_step: string;
    }
  | {
      kind: 'ready';
      title: string;
      message: string;
      next_step: string;
      artifact: WebScanSummaryArtifact;
    }
  | {
      kind: 'auth_denied' | 'missing_state' | 'backend_unavailable' | 'invalid_artifact';
      title: string;
      message: string;
      next_step: string;
    };

type ParamSource = URLSearchParams | Record<string, string | undefined>;

export const DEMO_ORG = 'acme';

export const DEMO_SCAN_PAYLOAD = {
  status: 'ok',
  target: {
    mode: 'org',
    value: DEMO_ORG,
  },
  posture_score: {
    score: 71,
  },
  repo_exposure_summaries: [
    {
      repo: 'acme/payments-api',
      exposure_score: 91,
    },
    {
      repo: 'acme/internal-platform',
      exposure_score: 74,
    },
    {
      repo: 'acme/customer-support-ai',
      exposure_score: 67,
    },
  ],
  top_findings: [
    {
      risk_score: 9.6,
      finding: {
        severity: 'high',
        summary: 'Headless agent workflow can write to protected deployment paths.',
        location: '.github/workflows/deploy-agent.yml',
      },
    },
    {
      risk_score: 8.4,
      finding: {
        severity: 'high',
        summary: 'MCP server exposes shell execution with repo-write credentials.',
        location: '.cursor/mcp.json',
      },
    },
    {
      risk_score: 7.2,
      finding: {
        severity: 'medium',
        summary: 'Org scan includes unreviewed AGENTS.md project markers.',
        location: 'payments-service/AGENTS.md',
      },
    },
  ],
} as const;

export const DEMO_ACTION_PAYLOAD = {
  summary: 'scheduled mode: posture score delta +1.50 (current 71.00); profile compliance delta +4.00% (current 88.00%)',
  posture_score: 71,
  compliance_percent: 88,
} as const;

export function normalizeOrg(input?: string): string {
  const trimmed = (input ?? '').trim();
  return trimmed === '' ? DEMO_ORG : trimmed;
}

export function buildCLICommand(org: string): string {
  return `wrkr scan --github-org ${normalizeOrg(org)} --github-api https://api.github.com --json`;
}

export function buildActionWorkflow(org: string): string {
  const targetOrg = normalizeOrg(org);
  return `name: wrkr-org-bootstrap
on:
  workflow_dispatch:

jobs:
  bootstrap:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: Clyra-AI/wrkr/action@v1
        with:
          mode: scheduled
          target_mode: org
          target_value: ${targetOrg}`;
}

export function buildBootstrapRequest(org: string, handoffMode: HandoffMode): BootstrapRequest {
  const targetOrg = normalizeOrg(org);
  return {
    schema_id: 'wrkr.web.bootstrap_request',
    schema_version: '1.0.0',
    transport: 'equivalent_handoff',
    target: {
      mode: 'github_org',
      value: targetOrg,
      read_only: true,
      required_scopes: ['metadata:read', 'contents:read'],
    },
    handoff: {
      mode: handoffMode,
      cli_command: buildCLICommand(targetOrg),
      github_action_workflow: buildActionWorkflow(targetOrg),
      return_contract: 'wrkr.web.scan_summary',
      return_schema_version: '1.0.0',
    },
    boundaries: [
      'Read-only bootstrap only; keep Go CLI authoritative for scan, risk, proof, and evidence.',
      'No runtime enforcement, hidden partial org scans, or persistent dashboard state.',
      'Paste or upload only machine-readable Wrkr output; do not paste secrets.',
    ],
  };
}

export function buildDemoHref(
  org: string,
  demo: 'success' | 'denied' | 'missing_state' | 'backend_unavailable',
): string {
  const encodedOrg = encodeURIComponent(normalizeOrg(org));
  if (demo === 'success') {
    return `/scan?org=${encodedOrg}&demo=success`;
  }
  return `/scan?org=${encodedOrg}&error=${demo}`;
}

export function projectSummaryArtifact(
  rawArtifact: string,
  expectedOrg?: string,
):
  | {
      ok: true;
      artifact: WebScanSummaryArtifact;
    }
  | {
      ok: false;
      code: 'invalid_json' | 'unsupported_contract';
      message: string;
    } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawArtifact);
  } catch {
    return {
      ok: false,
      code: 'invalid_json',
      message: 'Artifact input must be valid JSON.',
    };
  }

  const record = asRecord(parsed);
  if (!record) {
    return {
      ok: false,
      code: 'unsupported_contract',
      message: 'Artifact input must be a JSON object.',
    };
  }

  const artifact = projectSummaryRecord(record, normalizeOrg(expectedOrg));
  if (!artifact) {
    return {
      ok: false,
      code: 'unsupported_contract',
      message: 'Expected a Wrkr org scan JSON payload or a projected web summary artifact.',
    };
  }

  return { ok: true, artifact };
}

export function resolveBootstrapState(
  params: ParamSource,
  options: {
    artifactText?: string;
    org?: string;
  } = {},
): BootstrapState {
  const org = normalizeOrg(options.org ?? getParam(params, 'org'));
  const error = getParam(params, 'error');
  if (error === 'denied') {
    return {
      kind: 'auth_denied',
      title: 'Read-only access was denied',
      message: `GitHub read-only access for ${org} was denied before Wrkr handoff started.`,
      next_step: 'Retry the handoff or fall back to the CLI command below.',
    };
  }
  if (error === 'missing_state') {
    return {
      kind: 'missing_state',
      title: 'Callback state was missing',
      message: 'The bootstrap return path did not include the expected state marker, so Wrkr stayed fail-closed.',
      next_step: 'Restart the handoff and keep the generated bootstrap request intact.',
    };
  }
  if (error === 'backend_unavailable') {
    return {
      kind: 'backend_unavailable',
      title: 'The scan handoff endpoint was unavailable',
      message: 'Wrkr did not receive a summary artifact from the handoff target, so nothing was persisted or inferred.',
      next_step: 'Retry later or run the CLI command directly and paste the returned JSON.',
    };
  }

  const rawArtifact = normalizeArtifactInput(options.artifactText, getParam(params, 'demo'));
  if (rawArtifact !== '') {
    const projected = projectSummaryArtifact(rawArtifact, org);
    if (!projected.ok) {
      return {
        kind: 'invalid_artifact',
        title: 'Wrkr summary artifact could not be projected',
        message: projected.message,
        next_step: 'Paste `wrkr scan --github-org ... --json` output or use the example artifact.',
      };
    }
    return {
      kind: 'ready',
      title: 'Projected Wrkr summary artifact',
      message: 'This summary is derived from an existing Wrkr machine-readable contract and stays read-only.',
      next_step: 'Use the projected summary for quick review, then continue with `wrkr report`, `wrkr evidence`, and `wrkr verify` from the original scan state.',
      artifact: projected.artifact,
    };
  }

  return {
    kind: 'idle',
    title: 'Prepare a read-only org scan handoff',
    message: 'Generate an equivalent bootstrap request, trigger an existing Wrkr org scan contract, then paste the returned JSON here.',
    next_step: 'Choose CLI or GitHub Action handoff, run it, and paste the result into the summary panel.',
  };
}

function normalizeArtifactInput(artifactText: string | undefined, demo: string | undefined): string {
  const trimmed = (artifactText ?? '').trim();
  if (trimmed !== '') {
    return trimmed;
  }
  if (demo === 'success') {
    return JSON.stringify(DEMO_SCAN_PAYLOAD);
  }
  if (demo === 'action') {
    return JSON.stringify(DEMO_ACTION_PAYLOAD);
  }
  return '';
}

function projectSummaryRecord(record: Record<string, unknown>, expectedOrg: string): WebScanSummaryArtifact | null {
  if (record.schema_id === 'wrkr.web.scan_summary') {
    const existing = asSummaryArtifact(record);
    if (existing) {
      return existing;
    }
  }

  const target = asRecord(record.target);
  const targetMode = stringValue(target?.mode);
  if ((targetMode === 'org' || targetMode === 'github_org') && stringValue(record.status) !== '') {
    const findings = projectFindings(record.top_findings);
    return {
      schema_id: 'wrkr.web.scan_summary',
      schema_version: '1.0.0',
      source_contract: 'wrkr scan --github-org --json',
      org: stringValue(target?.value) || expectedOrg,
      status: stringValue(record.status) || 'ok',
      posture_score: numberValue(asRecord(record.posture_score)?.score) ?? 0,
      repo_count: repoCount(record.repo_exposure_summaries),
      top_findings: findings,
      summary: findings.length > 0
        ? `Projected ${findings.length} top finding(s) from the Wrkr org scan contract.`
        : 'Projected Wrkr org scan with no ranked findings in the supplied summary.',
    };
  }

  if (typeof record.summary === 'string' && typeof record.posture_score === 'number') {
    return {
      schema_id: 'wrkr.web.scan_summary',
      schema_version: '1.0.0',
      source_contract: 'wrkr action scheduled summary',
      org: expectedOrg,
      status: 'ok',
      posture_score: numberValue(record.posture_score) ?? 0,
      repo_count: 0,
      top_findings: [],
      summary: stringValue(record.summary) || 'Projected Wrkr action scheduled summary.',
    };
  }

  return null;
}

function asSummaryArtifact(record: Record<string, unknown>): WebScanSummaryArtifact | null {
  const org = stringValue(record.org);
  if (org === '') {
    return null;
  }
  return {
    schema_id: 'wrkr.web.scan_summary',
    schema_version: '1.0.0',
    source_contract:
      record.source_contract === 'wrkr action scheduled summary' || record.source_contract === 'wrkr.web.scan_summary'
        ? record.source_contract
        : 'wrkr scan --github-org --json',
    org,
    status: stringValue(record.status) || 'ok',
    posture_score: numberValue(record.posture_score) ?? 0,
    repo_count: numberValue(record.repo_count) ?? 0,
    top_findings: projectFindings(record.top_findings),
    summary: stringValue(record.summary) || 'Projected Wrkr web summary artifact.',
  };
}

function projectFindings(value: unknown): WebSummaryFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const findings: WebSummaryFinding[] = [];
  for (let index = 0; index < value.length && findings.length < 3; index += 1) {
    const finding = value[index];
    const record = asRecord(finding);
    if (!record) {
      continue;
    }
    const nested = asRecord(record.finding) ?? record;
    const summary = stringValue(nested.summary) || stringValue(nested.tool_type) || `finding ${index + 1}`;
    findings.push({
      severity: stringValue(nested.severity) || 'unknown',
      summary,
      location: stringValue(nested.location) || 'unknown',
      risk_score: numberValue(record.risk_score) ?? numberValue(nested.risk_score) ?? 0,
    });
  }
  return findings;
}

function repoCount(value: unknown): number {
  if (Array.isArray(value)) {
    return value.length;
  }
  return 0;
}

function getParam(params: ParamSource, key: string): string | undefined {
  if (params instanceof URLSearchParams) {
    return params.get(key) ?? undefined;
  }
  return params[key];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function numberValue(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}
