#!/usr/bin/env node
import { formatJson, formatRuleCatalogue } from './report/json.js';
import { formatSarif } from './report/sarif.js';
import { formatText } from './report/text.js';
import { RULES, RULE_IDS, isRuleId } from './rules.js';
import { collectFiles, DEFAULT_EXCLUDED_DIRS, DEFAULT_EXTENSIONS, scanFiles } from './scanner.js';
import { isSeverity, type RuleId, type ScanError, type Severity } from './types.js';
import { TOOL_NAME, VERSION } from './version.js';

const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_USAGE = 2;

type Format = 'text' | 'json' | 'sarif';

interface Options {
  format: Format;
  severityThreshold: Severity;
  rules: RuleId[];
  ignoreRules: RuleId[];
  extensions: string[];
  exitCode: boolean;
  color: boolean | null;
  uriBase: string | null;
}

class UsageError extends Error {}

const HELP = `${TOOL_NAME} ${VERSION}
Static detection of incomplete module denylists and unsafe context configuration in JavaScript
sandboxes built on node:vm, vm2 and isolated-vm.

Usage:
  ${TOOL_NAME} scan <paths...> [options]
  ${TOOL_NAME} rules [--format text|json]

Options:
  --format <text|json|sarif>     Output format (default: text).
  --severity-threshold <level>   Report findings at or above low|medium|high|critical
                                 (default: low).
  --rule <id>                    Run only these rules. Repeatable, comma-separated.
  --ignore-rule <id>             Skip these rules. Repeatable, comma-separated.
  --ext <list>                   Extensions to pick up when walking directories
                                 (default: ${DEFAULT_EXTENSIONS.join(',')}). Explicitly named
                                 files are always scanned.
  --exit-code                    Exit ${EXIT_FINDINGS} when any finding is reported, for CI.
  --sarif-uri-base <id>          Emit uriBaseId on SARIF locations (e.g. SRCROOT).
  --color / --no-color           Force or disable ANSI colour (default: auto).
  -h, --help                     Show this help.
  -v, --version                  Show the version.

Directories named ${DEFAULT_EXCLUDED_DIRS.join(', ')} are skipped while walking.

Exit codes:
  ${EXIT_OK}  completed (or findings reported without --exit-code)
  ${EXIT_FINDINGS}  findings reported and --exit-code was given
  ${EXIT_USAGE}  bad usage, or no input files
`;

function parseList(value: string): string[] {
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function parseRuleIds(value: string): RuleId[] {
  return parseList(value).map((candidate) => {
    const upper = candidate.toUpperCase();
    if (!isRuleId(upper)) {
      throw new UsageError(`unknown rule '${candidate}'. Known rules: ${RULE_IDS.join(', ')}`);
    }
    return upper;
  });
}

interface ParsedArgs {
  command: string | null;
  paths: string[];
  options: Options;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: readonly string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    command: null,
    paths: [],
    options: {
      format: 'text',
      severityThreshold: 'low',
      rules: [],
      ignoreRules: [],
      extensions: [...DEFAULT_EXTENSIONS],
      exitCode: false,
      color: null,
      uriBase: null,
    },
    help: false,
    version: false,
  };

  let index = 0;
  const next = (flag: string): string => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new UsageError(`${flag} requires a value`);
    }
    index += 1;
    return value;
  };

  for (; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === undefined) continue;

    if (!arg.startsWith('-')) {
      if (parsed.command === null) parsed.command = arg;
      else parsed.paths.push(arg);
      continue;
    }

    const eq = arg.indexOf('=');
    const flag = eq === -1 ? arg : arg.slice(0, eq);
    const inline = eq === -1 ? null : arg.slice(eq + 1);
    const value = (): string => inline ?? next(flag);

    switch (flag) {
      case '-h':
      case '--help':
        parsed.help = true;
        break;
      case '-v':
      case '--version':
        parsed.version = true;
        break;
      case '--format': {
        const format = value();
        if (format !== 'text' && format !== 'json' && format !== 'sarif') {
          throw new UsageError(`unknown format '${format}'. Use text, json or sarif.`);
        }
        parsed.options.format = format;
        break;
      }
      case '--severity-threshold': {
        const level = value().toLowerCase();
        if (!isSeverity(level)) {
          throw new UsageError(
            `unknown severity '${level}'. Use low, medium, high or critical.`,
          );
        }
        parsed.options.severityThreshold = level;
        break;
      }
      case '--rule':
        parsed.options.rules.push(...parseRuleIds(value()));
        break;
      case '--ignore-rule':
        parsed.options.ignoreRules.push(...parseRuleIds(value()));
        break;
      case '--ext':
        parsed.options.extensions = parseList(value()).map((ext) =>
          ext.startsWith('.') ? ext : `.${ext}`,
        );
        break;
      case '--exit-code':
        parsed.options.exitCode = true;
        break;
      case '--sarif-uri-base':
        parsed.options.uriBase = value();
        break;
      case '--color':
        parsed.options.color = true;
        break;
      case '--no-color':
        parsed.options.color = false;
        break;
      default:
        throw new UsageError(`unknown option '${flag}'`);
    }
  }

  return parsed;
}

function useColor(options: Options): boolean {
  if (options.color !== null) return options.color;
  if (process.env['NO_COLOR'] !== undefined) return false;
  return options.format === 'text' && process.stdout.isTTY === true;
}

function printRules(format: Format): void {
  if (format === 'json') {
    process.stdout.write(`${formatRuleCatalogue()}\n`);
    return;
  }
  for (const ruleId of RULE_IDS) {
    const rule = RULES[ruleId];
    process.stdout.write(`${rule.id}  ${rule.severity.padEnd(8)}  ${rule.name}\n`);
    process.stdout.write(`        ${rule.summary}\n\n`);
  }
}

function runScan(paths: readonly string[], options: Options): number {
  if (paths.length === 0) throw new UsageError('scan requires at least one path');

  const errors: ScanError[] = [];
  const onError = (error: ScanError): void => {
    errors.push(error);
  };

  const files = collectFiles(paths, options.extensions, new Set(DEFAULT_EXCLUDED_DIRS), onError);
  if (files.length === 0) {
    // Exit 2, as the help text says. Reporting "no findings" and exiting 0
    // means a CI gate goes green forever the first time a directory is
    // renamed -- which is the one failure mode a gate must not have.
    for (const error of errors) {
      process.stderr.write(`warning: ${error.file}: ${error.message}\n`);
    }
    throw new UsageError(
      `no input files matched ${paths.map((path) => JSON.stringify(path)).join(', ')}` +
        ` (extensions: ${options.extensions.join(', ')})`,
    );
  }
  const findings = scanFiles(files, {
    rules: options.rules,
    ignoreRules: options.ignoreRules,
    severityThreshold: options.severityThreshold,
    extensions: options.extensions,
    onError,
  });

  for (const error of errors) {
    process.stderr.write(`warning: ${error.file}: ${error.message}\n`);
  }

  if (options.format === 'json') {
    process.stdout.write(`${formatJson(findings, { filesScanned: files.length })}\n`);
  } else if (options.format === 'sarif') {
    process.stdout.write(
      `${formatSarif(findings, { uriBase: options.uriBase ?? undefined })}\n`,
    );
  } else {
    process.stdout.write(
      `${formatText(findings, { color: useColor(options), filesScanned: files.length })}\n`,
    );
  }

  // scanFiles already applied severityThreshold, so re-filtering here always
  // returned the same array.
  return options.exitCode && findings.length > 0 ? EXIT_FINDINGS : EXIT_OK;
}

function main(argv: readonly string[]): number {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${TOOL_NAME}: ${error.message}\n\nRun with --help for usage.\n`);
      return EXIT_USAGE;
    }
    throw error;
  }

  if (parsed.version) {
    process.stdout.write(`${VERSION}\n`);
    return EXIT_OK;
  }
  if (parsed.help || parsed.command === null) {
    process.stdout.write(HELP);
    return parsed.command === null && !parsed.help ? EXIT_USAGE : EXIT_OK;
  }

  try {
    switch (parsed.command) {
      case 'scan':
        return runScan(parsed.paths, parsed.options);
      case 'rules':
        if (parsed.options.format === 'sarif') {
          // SARIF describes results, not a catalogue. Printing the text table
          // instead of saying so left a script parsing plain text as JSON.
          throw new UsageError("'rules' supports --format text or json, not sarif");
        }
        printRules(parsed.options.format);
        return EXIT_OK;
      default:
        throw new UsageError(`unknown command '${parsed.command}'. Use 'scan' or 'rules'.`);
    }
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${TOOL_NAME}: ${error.message}\n\nRun with --help for usage.\n`);
      return EXIT_USAGE;
    }
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${TOOL_NAME}: ${message}\n`);
    return EXIT_USAGE;
  }
}

// Piping into a command that exits early (`| head`) closes stdout under us. That is a normal
// way to use a CLI, not an error worth a stack trace.
process.stdout.on('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EPIPE') process.exit(EXIT_OK);
  throw error;
});

process.exitCode = main(process.argv.slice(2));
