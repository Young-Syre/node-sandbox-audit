import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { FileContext } from './context.js';
import { DETECTORS } from './detectors/index.js';
import {
  severityRank,
  type Finding,
  type RuleId,
  type ScanFilesOptions,
  type ScanOptions,
} from './types.js';

export const DEFAULT_EXTENSIONS: readonly string[] = ['.js', '.mjs', '.cjs'];

export const DEFAULT_EXCLUDED_DIRS: readonly string[] = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  'out',
];

function enabledRules(options: ScanOptions | undefined): Set<RuleId> {
  const selected = options?.rules;
  const ignored = new Set(options?.ignoreRules ?? []);
  const base =
    selected && selected.length > 0
      ? new Set<RuleId>(selected)
      : new Set<RuleId>(DETECTORS.map((detector) => detector.ruleId));
  for (const ruleId of ignored) base.delete(ruleId);
  return base;
}

function compareFindings(a: Finding, b: Finding): number {
  return (
    a.file.localeCompare(b.file) ||
    a.start.line - b.start.line ||
    a.start.column - b.start.column ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

/** Analyses a single source string. Throws a `SyntaxError` when the source cannot be parsed. */
export function scanSource(
  code: string,
  filename = '<input>',
  options?: ScanOptions,
): Finding[] {
  const rules = enabledRules(options);
  const threshold = severityRank(options?.severityThreshold ?? 'low');
  const ctx = FileContext.parse(code, filename);

  const findings: Finding[] = [];
  for (const detector of DETECTORS) {
    if (!rules.has(detector.ruleId)) continue;
    for (const finding of detector.detect(ctx)) {
      if (severityRank(finding.severity) >= threshold) findings.push(finding);
    }
  }
  return findings.sort(compareFindings);
}

/**
 * Analyses files and directories. Directories are walked recursively. Unreadable or unparseable
 * files are reported through `options.onError` and skipped rather than aborting the scan.
 */
export function scanFiles(paths: readonly string[], options?: ScanFilesOptions): Finding[] {
  const extensions = options?.extensions ?? DEFAULT_EXTENSIONS;
  const excluded = new Set(options?.excludeDirs ?? DEFAULT_EXCLUDED_DIRS);
  const findings: Finding[] = [];

  for (const file of collectFiles(paths, extensions, excluded, options?.onError)) {
    let source: string;
    try {
      source = readFileSync(file, 'utf8');
    } catch (error) {
      options?.onError?.({ file, message: errorMessage(error) });
      continue;
    }
    try {
      findings.push(...scanSource(source, file, options));
    } catch (error) {
      options?.onError?.({ file, message: `parse error: ${errorMessage(error)}` });
    }
  }

  return findings.sort(compareFindings);
}

/** Resolves paths to a de-duplicated, sorted list of files to analyse. */
export function collectFiles(
  paths: readonly string[],
  extensions: readonly string[],
  excluded: ReadonlySet<string>,
  onError?: ((error: { file: string; message: string }) => void) | undefined,
): string[] {
  const found = new Set<string>();

  const visit = (path: string, explicit: boolean): void => {
    let stats;
    try {
      stats = statSync(path);
    } catch (error) {
      onError?.({ file: path, message: errorMessage(error) });
      return;
    }

    if (stats.isDirectory()) {
      let entries;
      try {
        entries = readdirSync(path, { withFileTypes: true });
      } catch (error) {
        onError?.({ file: path, message: errorMessage(error) });
        return;
      }
      for (const entry of entries) {
        if (entry.isDirectory() && excluded.has(entry.name)) continue;
        visit(join(path, entry.name), false);
      }
      return;
    }

    if (!stats.isFile()) return;
    // An explicitly named file is always scanned; discovered files must match an extension.
    if (explicit || extensions.some((ext) => path.endsWith(ext))) found.add(path);
  };

  for (const path of paths) visit(path, true);
  return [...found].sort();
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
