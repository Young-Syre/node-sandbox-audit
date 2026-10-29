import { stripNodePrefix } from '../builtins.js';
import { REALM_ESCAPE_MODULES } from '../builtins.js';
import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';
import { describeCollection, moduleDenylists } from './denylist.js';

export function detect(ctx: FileContext): Finding[] {
  const findings: Finding[] = [];

  for (const collection of moduleDenylists(ctx)) {
    const label = describeCollection(collection);
    const written = new Set(collection.entries.map((entry) => entry.value));
    const mentioned = new Set(collection.entries.map((entry) => stripNodePrefix(entry.value)));

    const missing = REALM_ESCAPE_MODULES.filter((module) => !mentioned.has(module.name));
    if (missing.length > 0) {
      const names = missing.map((module) => `\`${module.name}\``).join(', ');
      const details = missing.map(
        (module) => `${module.name} (${module.kind}): ${module.mechanism}`,
      );
      if (mentioned.has('vm') === false) {
        details.unshift(
          'Shortest chain: `const vm = await import("node:vm")` then ' +
            '`vm.runInThisContext("process")` returns the *host* process object, after which ' +
            '`process.mainModule.require("child_process")` loads anything the list denied.',
        );
      }
      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA001',
          node: collection.node,
          message:
            `Module denylist ${label} blocks ${collection.entries.length} specifier(s) but omits ` +
            `${missing.length} realm-escape module(s): ${names}. Reaching any one of them is ` +
            'equivalent to loading every module the list denies.',
          details,
        }),
      );
    }

    const prefixGaps = collection.entries
      .filter((entry) => {
        const bare = stripNodePrefix(entry.value);
        return written.has(bare) !== written.has(`node:${bare}`);
      })
      .filter((entry, index, all) => all.findIndex((e) => e.value === entry.value) === index);

    if (prefixGaps.length > 0) {
      const anchor = prefixGaps[0];
      if (!anchor) continue;
      const details = prefixGaps.map((entry) => {
        const bare = stripNodePrefix(entry.value);
        const missingSpelling = written.has(bare) ? `node:${bare}` : bare;
        return `\`${entry.value}\` is blocked but \`${missingSpelling}\` is not, and both resolve to the same module.`;
      });
      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA001',
          node: anchor.node,
          message:
            `Module denylist ${label} blocks ${prefixGaps.length} specifier(s) under only one of ` +
            'their two spellings; the other spelling bypasses the check.',
          details,
          remediation:
            'Normalise the specifier before comparing — strip a leading `node:` and reject any ' +
            'specifier that is not in an allowlist — rather than listing both spellings by hand.',
        }),
      );
    }
  }

  return findings;
}
