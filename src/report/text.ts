import { RULES } from '../rules.js';
import { SEVERITIES, severityRank, type Finding, type Severity } from '../types.js';

export interface TextReportOptions {
  color: boolean;
  filesScanned: number;
}

const WRAP_WIDTH = 96;

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: '\u001b[1;31m',
  high: '\u001b[31m',
  medium: '\u001b[33m',
  low: '\u001b[36m',
};

const RESET = '\u001b[0m';
const DIM = '\u001b[2m';
const BOLD = '\u001b[1m';

class Painter {
  constructor(private readonly enabled: boolean) {}

  severity(severity: Severity): string {
    const padded = severity.padEnd(8, ' ');
    return this.enabled ? `${SEVERITY_STYLE[severity]}${padded}${RESET}` : padded;
  }

  dim(text: string): string {
    return this.enabled ? `${DIM}${text}${RESET}` : text;
  }

  bold(text: string): string {
    return this.enabled ? `${BOLD}${text}${RESET}` : text;
  }
}

function wrap(text: string, width: number, indent: string): string[] {
  const words = text.split(/\s+/).filter((word) => word.length > 0);
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current = `${current} ${word}`;
    } else {
      lines.push(indent + current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(indent + current);
  return lines;
}

function indentBlock(text: string, indent: string): string[] {
  return text.split('\n').map((line) => indent + line);
}

function pluralise(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

export function formatText(findings: readonly Finding[], options: TextReportOptions): string {
  const paint = new Painter(options.color);
  const out: string[] = [];

  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    const bucket = byFile.get(finding.file);
    if (bucket) bucket.push(finding);
    else byFile.set(finding.file, [finding]);
  }

  for (const [file, fileFindings] of byFile) {
    out.push(paint.bold(file));
    for (const finding of fileFindings) {
      const position = paint.dim(`${finding.start.line}:${finding.start.column}`);
      out.push(
        `  ${paint.severity(finding.severity)} ${finding.ruleId}  ` +
          `${paint.dim(finding.ruleName)}  ${position}`,
      );
      out.push(...wrap(finding.message, WRAP_WIDTH, '    '));
      for (const detail of finding.details) {
        const lines = wrap(detail, WRAP_WIDTH - 2, '');
        lines.forEach((line, index) => {
          out.push(index === 0 ? `      · ${line}` : `        ${line}`);
        });
      }
      out.push('');
      out.push(...indentBlock(finding.codeFrame, '    ').map((line) => paint.dim(line)));
      out.push('');
      out.push(...wrap(`fix: ${finding.remediation}`, WRAP_WIDTH, '    '));
      out.push('');
    }
  }

  const counts = new Map<Severity, number>();
  for (const finding of findings) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }
  const breakdown = [...SEVERITIES]
    .sort((a, b) => severityRank(b) - severityRank(a))
    .filter((severity) => (counts.get(severity) ?? 0) > 0)
    .map((severity) => `${counts.get(severity) ?? 0} ${severity}`)
    .join(', ');

  const scanned = pluralise(options.filesScanned, 'file');
  if (findings.length === 0) {
    out.push(`No findings. ${scanned} scanned.`);
  } else {
    out.push(
      `${pluralise(findings.length, 'finding')} (${breakdown}) ` +
        `in ${pluralise(byFile.size, 'file')}. ${scanned} scanned.`,
    );
    const ruleIds = [...new Set(findings.map((finding) => finding.ruleId))].sort();
    out.push(
      paint.dim(
        `rules fired: ${ruleIds.map((id) => `${id} ${RULES[id].name}`).join(', ')}`,
      ),
    );
  }

  return out.join('\n');
}
