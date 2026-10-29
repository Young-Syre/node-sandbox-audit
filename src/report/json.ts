import { RULES } from '../rules.js';
import type { Finding, Severity } from '../types.js';
import { TOOL_NAME, TOOL_URI, VERSION } from '../version.js';

export interface JsonReportOptions {
  filesScanned: number;
}

export interface JsonReport {
  tool: { name: string; version: string; informationUri: string };
  summary: {
    filesScanned: number;
    findings: number;
    bySeverity: Record<Severity, number>;
    byRule: Record<string, number>;
  };
  findings: Finding[];
}

export function buildJsonReport(
  findings: readonly Finding[],
  options: JsonReportOptions,
): JsonReport {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byRule: Record<string, number> = {};

  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byRule[finding.ruleId] = (byRule[finding.ruleId] ?? 0) + 1;
  }

  return {
    tool: { name: TOOL_NAME, version: VERSION, informationUri: TOOL_URI },
    summary: {
      filesScanned: options.filesScanned,
      findings: findings.length,
      bySeverity,
      byRule,
    },
    findings: [...findings],
  };
}

export function formatJson(findings: readonly Finding[], options: JsonReportOptions): string {
  return JSON.stringify(buildJsonReport(findings, options), null, 2);
}

/** The rule catalogue, for `nsa rules --format json`. */
export function formatRuleCatalogue(): string {
  return JSON.stringify(Object.values(RULES), null, 2);
}
