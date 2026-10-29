import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';

const KIND_LABEL = {
  import: 'imported',
  require: 'required',
  'dynamic-import': 'dynamically imported',
} as const;

export function detect(ctx: FileContext): Finding[] {
  return ctx.moduleRequests
    .filter((request) => request.module === 'vm2' || request.module.startsWith('vm2/'))
    .map((request) =>
      createFinding(ctx, {
        ruleId: 'NSA006',
        node: request.node,
        message:
          `\`${request.specifier}\` is ${KIND_LABEL[request.kind]} here. vm2 is discontinued and ` +
          'must not be used to run untrusted code.',
        details: [
          'vm2 ran guest code in the same V8 isolate as the host and tried to make that safe with ' +
            'proxies over host objects. That design was defeated repeatedly, and the project was ' +
            'withdrawn rather than patched again.',
          'Its own README now tells users to migrate away, and no further security fixes are ' +
            'published.',
        ],
      }),
    );
}
