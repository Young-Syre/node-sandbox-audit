/**
 * node-sandbox-audit — static detection of incomplete module denylists and unsafe context
 * configuration in JavaScript sandboxes built on `node:vm`, `vm2` and `isolated-vm`.
 */

export { scanSource, scanFiles, collectFiles, DEFAULT_EXTENSIONS, DEFAULT_EXCLUDED_DIRS } from './scanner.js';
export { RULES, RULE_IDS, isRuleId } from './rules.js';
export { REALM_ESCAPE_MODULES, REALM_ESCAPE_NAMES, realmEscape } from './builtins.js';
export { FileContext } from './context.js';
export { DETECTORS } from './detectors/index.js';
export { formatText } from './report/text.js';
export { formatJson, buildJsonReport, formatRuleCatalogue } from './report/json.js';
export { formatSarif, buildSarifReport } from './report/sarif.js';
export { VERSION, TOOL_NAME, TOOL_URI } from './version.js';
export { SEVERITIES, severityRank, isSeverity } from './types.js';

export type {
  Finding,
  Rule,
  RuleId,
  ScanError,
  ScanFilesOptions,
  ScanOptions,
  Severity,
  SourcePosition,
} from './types.js';
export type { EscapeKind, RealmEscapeModule } from './builtins.js';
export type { Detector } from './detectors/index.js';
export type { JsonReport, JsonReportOptions } from './report/json.js';
export type { SarifReportOptions } from './report/sarif.js';
export type { TextReportOptions } from './report/text.js';
