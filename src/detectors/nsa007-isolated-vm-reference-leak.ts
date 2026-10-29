import {
  isLiteral,
  memberPath,
  propertyName,
  type Literal,
  type NewExpression,
  type ObjectExpression,
  type Property,
} from '../ast.js';
import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';

/** Transfer options that cross the isolate boundary by reference instead of by copy. */
const BRIDGE_OPTIONS: Record<string, boolean> = {
  copy: false,
  reference: true,
};

function usesIsolatedVm(ctx: FileContext): boolean {
  return ctx.moduleRequests.some((request) => request.module === 'isolated-vm');
}

export function detect(ctx: FileContext): Finding[] {
  if (!usesIsolatedVm(ctx)) return [];

  const findings: Finding[] = [];

  ctx.walk((node) => {
    if (node.type === 'NewExpression') {
      const construct = node as NewExpression;
      const identity = ctx.resolveCallee(construct.callee);
      if (identity?.module !== 'isolated-vm' || identity.member !== 'Reference') return;
      const target = construct.arguments[0];
      const path = target ? memberPath(target) : null;
      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA007',
          node,
          message:
            `\`new ivm.Reference(${path === null ? '…' : path.join('.')})\` exposes a ` +
            'host-realm value to the isolate by reference, which is the one thing isolate ' +
            'separation was buying.',
          details: [
            'A reference to a host function is callable from the isolate via `applySync` / ' +
              '`apply`, and a reference to a host object exposes its prototype chain through ' +
              '`getSync`.',
            'If the referenced value is a function, the isolate can call it with arguments of its ' +
              'choosing — including arguments the host code never expected to validate.',
          ],
        }),
      );
      return;
    }

    if (node.type !== 'ObjectExpression') return;
    for (const member of (node as ObjectExpression).properties) {
      if (member.type !== 'Property') continue;
      const property = member as Property;
      const key = propertyName(property.key, property.computed);
      if (key === null || !Object.prototype.hasOwnProperty.call(BRIDGE_OPTIONS, key)) continue;
      if (!isLiteral(property.value)) continue;
      if ((property.value as Literal).value !== BRIDGE_OPTIONS[key]) continue;

      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA007',
          node: property,
          message:
            `\`${key}: ${String(BRIDGE_OPTIONS[key])}\` transfers across the isolate boundary by ` +
            'reference rather than by copy, reintroducing a live bridge between the two realms.',
          details: [
            'Only copied values keep the isolates independent. A transferred reference is a handle ' +
              'that the other side can dereference and call.',
          ],
        }),
      );
    }
  });

  return findings;
}
