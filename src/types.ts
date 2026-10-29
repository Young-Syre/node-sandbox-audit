/**
 * Public types for node-sandbox-audit.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type RuleId =
  | 'NSA001'
  | 'NSA002'
  | 'NSA003'
  | 'NSA004'
  | 'NSA005'
  | 'NSA006'
  | 'NSA007'
  | 'NSA008';

const SEVERITY_RANK: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity];
}

export function isSeverity(value: string): value is Severity {
  return Object.prototype.hasOwnProperty.call(SEVERITY_RANK, value);
}

/** 1-based line, 1-based column. */
export interface SourcePosition {
  line: number;
  column: number;
}

export interface Rule {
  id: RuleId;
  /** Stable kebab-case name, used in SARIF and in the rules table. */
  name: string;
  severity: Severity;
  /** What the rule catches. */
  summary: string;
  /** Why it matters — the security argument, not a restatement of the summary. */
  rationale: string;
  /** Default remediation, used when a finding does not supply a more specific one. */
  remediation: string;
  helpUri: string;
}

export interface Finding {
  ruleId: RuleId;
  ruleName: string;
  severity: Severity;
  /** One-line description of this specific occurrence. */
  message: string;
  /** Per-occurrence detail lines, e.g. the exact escapes reachable. May be empty. */
  details: string[];
  remediation: string;
  /** Path as supplied to the scanner. */
  file: string;
  start: SourcePosition;
  end: SourcePosition;
  /** The offending source text, single-lined and length-capped. */
  snippet: string;
  /** Rendered code frame with a caret under the offending node. */
  codeFrame: string;
}

export interface ScanError {
  file: string;
  message: string;
}

export interface ScanOptions {
  /** Only these rules run. Empty or undefined means all rules. */
  rules?: readonly RuleId[] | undefined;
  /** These rules never run. Applied after `rules`. */
  ignoreRules?: readonly RuleId[] | undefined;
  /** Drop findings below this severity. Defaults to 'low' (keep everything). */
  severityThreshold?: Severity | undefined;
}

export interface ScanFilesOptions extends ScanOptions {
  /** File extensions to pick up when a path is a directory. */
  extensions?: readonly string[] | undefined;
  /** Directory names skipped during traversal. */
  excludeDirs?: readonly string[] | undefined;
  /** Called for files that could not be read or parsed, instead of throwing. */
  onError?: ((error: ScanError) => void) | undefined;
}
