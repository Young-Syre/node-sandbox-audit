import type { AstNode } from './ast.js';
import type { FileContext } from './context.js';
import { extractSnippet, renderCodeFrame } from './frame.js';
import { RULES } from './rules.js';
import type { Finding, RuleId, Severity, SourcePosition } from './types.js';

export interface FindingInput {
  ruleId: RuleId;
  node: AstNode;
  message: string;
  details?: readonly string[];
  /** Overrides the rule's default remediation when a more specific fix applies. */
  remediation?: string;
  /**
   * Overrides the rule's default severity when the code carries a mitigation the
   * rule's rationale depends on being absent.
   */
  severity?: Severity;
}

/** acorn reports 0-based columns; findings and code frames use 1-based. */
function positionOf(node: AstNode, which: 'start' | 'end'): SourcePosition {
  const loc = node.loc?.[which];
  if (!loc) return { line: 1, column: 1 };
  return { line: loc.line, column: loc.column + 1 };
}

export function createFinding(ctx: FileContext, input: FindingInput): Finding {
  const rule = RULES[input.ruleId];
  const start = positionOf(input.node, 'start');
  const end = positionOf(input.node, 'end');
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: input.severity ?? rule.severity,
    message: input.message,
    details: [...(input.details ?? [])],
    remediation: input.remediation ?? rule.remediation,
    file: ctx.filename,
    start,
    end,
    snippet: extractSnippet(ctx.source, input.node.start, input.node.end),
    codeFrame: renderCodeFrame(ctx.lines, start, end),
  };
}
