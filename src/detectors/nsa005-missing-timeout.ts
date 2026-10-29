import { argAt, objectHasSpread, objectProperty } from '../ast.js';
import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';
import { vmCalls } from './vmcalls.js';

export function detect(ctx: FileContext): Finding[] {
  const findings: Finding[] = [];

  for (const vmCall of vmCalls(ctx)) {
    if (!vmCall.supportsTimeout) continue;

    const options = argAt(vmCall.call.arguments, vmCall.optionsIndex);

    // A non-literal options bag may well carry a timeout; reporting it would be a guess.
    if (options !== null && options.type !== 'ObjectExpression') continue;
    if (options !== null && objectHasSpread(options)) continue;
    if (objectProperty(options, 'timeout') !== null) continue;

    findings.push(
      createFinding(ctx, {
        ruleId: 'NSA005',
        node: vmCall.call,
        message:
          `\`${vmCall.kind}\` has no \`timeout\` option, so guest code can hold the calling ` +
          'thread indefinitely.',
        details: [
          'One request containing `while (true) {}` is enough to stop the event loop for every ' +
            'other request served by the same thread.',
        ],
      }),
    );
  }

  return findings;
}
