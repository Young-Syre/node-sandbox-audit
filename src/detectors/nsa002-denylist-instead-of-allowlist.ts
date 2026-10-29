import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';
import { describeCollection, moduleDenylists } from './denylist.js';

export function detect(ctx: FileContext): Finding[] {
  return moduleDenylists(ctx).map((collection) => {
    const inferred =
      collection.polaritySource === 'usage'
        ? ' (inferred from the polarity of the membership test against it)'
        : '';
    return createFinding(ctx, {
      ruleId: 'NSA002',
      node: collection.node,
      message:
        `Module import filtering is expressed as a denylist in ${describeCollection(collection)}` +
        `${inferred}. A denylist is only correct while it is complete, and completeness cannot be ` +
        'established for the Node builtin surface.',
      details: [
        'The denied set must be closed under every alias and re-export: the `node:` prefix, ' +
          'deep paths, and any module that returns a value created in another realm.',
        'The permitted set is usually tiny and known — which is why inverting the check is both ' +
          'sound and cheaper to review.',
      ],
    });
  });
}
