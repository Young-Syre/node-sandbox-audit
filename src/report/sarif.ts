import { createHash } from 'node:crypto';

import { RULES, RULE_IDS } from '../rules.js';
import type { Finding, RuleId, Severity } from '../types.js';
import { TOOL_NAME, TOOL_URI, VERSION } from '../version.js';

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

/** SARIF only defines these four levels, so severity has to be mapped onto them. */
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const LEVEL_BY_SEVERITY: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

/**
 * GitHub code scanning reads `security-severity` (a CVSS-like 0-10 number) to decide which
 * alerts to surface, since SARIF's own `level` has no "critical".
 */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.3',
  high: '7.5',
  medium: '5.3',
  low: '3.1',
};

export interface SarifReportOptions {
  /** Repository-relative paths are what code scanning expects. */
  uriBase?: string | undefined;
}

function toUri(file: string): string {
  const normalised = file.replace(/\\/g, '/').replace(/^\.\//, '');
  return normalised.startsWith('/') ? `file://${normalised}` : normalised;
}

function fingerprint(finding: Finding): string {
  return createHash('sha256')
    .update(`${finding.ruleId}\u0000${toUri(finding.file)}\u0000${finding.snippet}`)
    .digest('hex')
    .slice(0, 16);
}

function messageText(finding: Finding): string {
  const parts = [finding.message, ...finding.details, `Fix: ${finding.remediation}`];
  return parts.join('\n\n');
}

function driverRule(ruleId: RuleId): Record<string, unknown> {
  const rule = RULES[ruleId];
  return {
    id: rule.id,
    name: rule.name,
    shortDescription: { text: rule.summary },
    fullDescription: { text: `${rule.summary} ${rule.rationale}` },
    help: {
      text: `${rule.rationale}\n\nFix: ${rule.remediation}`,
      markdown: `${rule.rationale}\n\n**Fix:** ${rule.remediation}`,
    },
    helpUri: rule.helpUri,
    defaultConfiguration: { level: LEVEL_BY_SEVERITY[rule.severity] },
    properties: {
      tags: ['security', 'sandbox', 'nodejs', `severity/${rule.severity}`],
      'security-severity': SECURITY_SEVERITY[rule.severity],
      precision: 'high',
    },
  };
}

export function buildSarifReport(
  findings: readonly Finding[],
  options: SarifReportOptions = {},
): Record<string, unknown> {
  const ruleIndex = new Map<RuleId, number>(RULE_IDS.map((id, index) => [id, index]));

  const results = findings.map((finding) => ({
    ruleId: finding.ruleId,
    ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
    level: LEVEL_BY_SEVERITY[finding.severity],
    message: { text: messageText(finding) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: toUri(finding.file),
            ...(options.uriBase === undefined ? {} : { uriBaseId: options.uriBase }),
          },
          region: {
            startLine: finding.start.line,
            startColumn: finding.start.column,
            endLine: finding.end.line,
            endColumn: finding.end.column,
            snippet: { text: finding.snippet },
          },
        },
      },
    ],
    partialFingerprints: { nodeSandboxAudit_v1: fingerprint(finding) },
  }));

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: VERSION,
            semanticVersion: VERSION,
            informationUri: TOOL_URI,
            rules: RULE_IDS.map(driverRule),
          },
        },
        columnKind: 'utf16CodeUnits',
        results,
      },
    ],
  };
}

export function formatSarif(
  findings: readonly Finding[],
  options: SarifReportOptions = {},
): string {
  return JSON.stringify(buildSarifReport(findings, options), null, 2);
}
