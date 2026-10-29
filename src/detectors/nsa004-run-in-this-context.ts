import { argAt, objectHasSpread, objectProperty } from '../ast.js';
import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';
import { vmCalls } from './vmcalls.js';

export function detect(ctx: FileContext): Finding[] {
  const findings: Finding[] = [];

  for (const vmCall of vmCalls(ctx)) {
    if (!vmCall.hostRealmByDefault) continue;

    if (vmCall.kind === 'vm.compileFunction') {
      const options = argAt(vmCall.call.arguments, vmCall.optionsIndex);
      // Only report when the options bag is a literal we can read and `parsingContext` is absent.
      if (options !== null && options.type !== 'ObjectExpression') continue;
      if (options !== null && objectHasSpread(options)) continue;
      if (objectProperty(options, 'parsingContext') !== null) continue;

      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA004',
          node: vmCall.call,
          message:
            '`vm.compileFunction` without `parsingContext` compiles the function in the calling ' +
            'realm, so the returned function closes over the host global scope.',
          details: [
            '`contextExtensions` does not change the realm — it only adds `with`-style scopes on ' +
              'top of the host global.',
          ],
        }),
      );
      continue;
    }

    findings.push(
      createFinding(ctx, {
        ruleId: 'NSA004',
        node: vmCall.call,
        message:
          `\`${vmCall.kind}\` evaluates its argument in the calling realm. The global scope of ` +
          'the evaluated code is the host global scope, so this is not a sandbox.',
        details: [
          'This is the pivot that turns an incomplete import denylist into a full escape: guest ' +
            'code that reaches `node:vm` calls `runInThisContext("process")` and receives the ' +
            'host `process` object, even though `process` was on the denylist.',
          'From there `process.mainModule.require` reloads any module, `process.stdout.write` ' +
            "forges traffic on the host's output channel, and `process.exit` stops the host.",
        ],
      }),
    );
  }

  return findings;
}
