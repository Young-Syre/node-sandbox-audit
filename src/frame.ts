import type { SourcePosition } from './types.js';

const CONTEXT_LINES = 2;
const MAX_CARET_WIDTH = 100;
const MAX_SNIPPET_LENGTH = 140;

/** Tabs are rendered 1:1 so that column arithmetic stays aligned with the caret row. */
function renderLine(line: string): string {
  return line.replace(/\t/g, ' ');
}

/**
 * Renders a code frame with a caret row under the offending node:
 *
 * ```
 *    7 |   const code = await readFile(entry, 'utf8');
 *    8 |   const BLOCKED = new Set(['process', 'child_process']);
 *      |                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *    9 |   const context = vm.createContext({});
 * ```
 */
export function renderCodeFrame(
  lines: readonly string[],
  start: SourcePosition,
  end: SourcePosition,
): string {
  const firstLine = Math.max(1, start.line - CONTEXT_LINES);
  const lastLine = Math.min(lines.length, start.line + CONTEXT_LINES);
  const gutterWidth = String(lastLine).length;
  const out: string[] = [];

  for (let lineNo = firstLine; lineNo <= lastLine; lineNo += 1) {
    const text = renderLine(lines[lineNo - 1] ?? '');
    out.push(`${String(lineNo).padStart(gutterWidth, ' ')} | ${text}`);
    if (lineNo !== start.line) continue;

    const caretStart = Math.max(0, start.column - 1);
    const sameLine = end.line === start.line;
    const rawWidth = sameLine ? end.column - start.column : text.length - caretStart;
    const width = Math.min(MAX_CARET_WIDTH, Math.max(1, rawWidth));
    out.push(`${' '.repeat(gutterWidth)} | ${' '.repeat(caretStart)}${'^'.repeat(width)}`);
  }

  return out.join('\n');
}

/** The offending source text, collapsed to one line and length-capped. */
export function extractSnippet(source: string, startOffset: number, endOffset: number): string {
  const raw = source.slice(startOffset, endOffset).replace(/\s+/g, ' ').trim();
  return raw.length > MAX_SNIPPET_LENGTH ? `${raw.slice(0, MAX_SNIPPET_LENGTH - 1)}…` : raw;
}
