import {
  argAt,
  isFunctionish,
  isIdentifier,
  isLiteral,
  isMember,
  memberPath,
  propertyName,
  rootIdentifier,
  type AssignmentExpression,
  type AstNode,
  type CallExpression,
  type NewExpression,
  type ObjectExpression,
  type Property,
} from '../ast.js';
import { HOST_GLOBALS, HOST_INTRINSICS } from '../builtins.js';
import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';
import { contextObjectLiterals } from './nsa003-empty-or-leaky-context.js';

/** Globals that exist in the host realm and whose prototype chain leads to host `Function`. */
const HOST_REALM_GLOBALS: ReadonlySet<string> = new Set([
  'Object',
  'Function',
  'Array',
  'String',
  'Number',
  'Boolean',
  'Symbol',
  'BigInt',
  'Date',
  'RegExp',
  'Error',
  'TypeError',
  'Promise',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'WeakRef',
  'ArrayBuffer',
  'SharedArrayBuffer',
  'DataView',
  'Proxy',
  'Reflect',
  'JSON',
  'Math',
  'Intl',
  'WebAssembly',
  'AbortController',
  'URL',
  'TextEncoder',
  'TextDecoder',
]);

const BRIDGE_DETAILS = [
  'Guest code only needs one host-realm object: ' +
    '`bridge.constructor.constructor("return process")()` compiles in the realm that owns ' +
    "`bridge`'s prototype chain, which is the host realm.",
  'Freezing the object does not help — the prototype chain is still reachable, and ' +
    '`Object.getPrototypeOf` is not something the sandbox can take away.',
];

interface HostValue {
  description: string;
}

function classifyHostValue(ctx: FileContext, node: AstNode): HostValue | null {
  if (isFunctionish(node)) {
    return { description: 'a function defined in the host realm' };
  }
  if (node.type === 'NewExpression') {
    const callee = (node as NewExpression).callee;
    return ctx.isHostValue(callee) || isIdentifier(callee)
      ? { description: 'an instance of a host-realm class' }
      : null;
  }

  const path = memberPath(node);
  if (path !== null && path[path.length - 1] === 'prototype') {
    return { description: `the host-realm prototype \`${path.join('.')}\`` };
  }

  const root = rootIdentifier(node);
  if (root === null) return null;
  if (HOST_GLOBALS.has(root.name) || HOST_INTRINSICS.has(root.name)) {
    return { description: `the host value \`${path?.join('.') ?? root.name}\`` };
  }
  if (HOST_REALM_GLOBALS.has(root.name)) {
    return { description: `the host intrinsic \`${path?.join('.') ?? root.name}\`` };
  }
  if (ctx.isHostValue(node)) {
    return { description: `the host-realm value \`${path?.join('.') ?? root.name}\`` };
  }
  return null;
}

/** An object literal whose every value is a primitive, which is safe to copy in. */
function isPrimitiveOnlyObject(node: AstNode | null): boolean {
  if (node?.type !== 'ObjectExpression') return false;
  return (node as ObjectExpression).properties.every(
    (member) => member.type === 'Property' && isLiteral((member as Property).value),
  );
}

function sandboxTargetName(ctx: FileContext, node: AstNode): string | null {
  if (isIdentifier(node)) return ctx.sandboxVars.has(node.name) ? node.name : null;
  if (!isMember(node)) return null;
  const root = rootIdentifier(node);
  if (root === null || !ctx.sandboxVars.has(root.name)) return null;
  return memberPath(node)?.join('.') ?? root.name;
}

export function detect(ctx: FileContext): Finding[] {
  const findings: Finding[] = [];

  ctx.walk((node) => {
    if (node.type === 'AssignmentExpression') {
      const assignment = node as AssignmentExpression;
      if (!isMember(assignment.left)) return;
      const target = sandboxTargetName(ctx, assignment.left.object);
      if (target === null) return;

      const key = propertyName(assignment.left.property, assignment.left.computed);
      if (key === '__proto__') {
        findings.push(
          createFinding(ctx, {
            ruleId: 'NSA008',
            node,
            message:
              `Assigning to \`${target}.__proto__\` replaces the prototype of the sandbox ` +
              'global with a host-realm object.',
            details: BRIDGE_DETAILS,
          }),
        );
        return;
      }

      const hostValue = classifyHostValue(ctx, assignment.right);
      if (hostValue === null) return;
      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA008',
          node,
          message:
            `\`${target}.${key ?? '[computed]'}\` is assigned ${hostValue.description}, placing a ` +
            'host-realm object on the sandbox global.',
          details: BRIDGE_DETAILS,
        }),
      );
      return;
    }

    if (node.type !== 'CallExpression') return;
    const call = node as CallExpression;
    const path = memberPath(call.callee)?.join('.');
    if (path !== 'Object.assign' && path !== 'Object.setPrototypeOf') return;

    const target = sandboxTargetName(ctx, argAt(call.arguments, 0) ?? node);
    if (target === null) return;

    if (path === 'Object.setPrototypeOf') {
      const proto = argAt(call.arguments, 1);
      if (proto !== null && isLiteral(proto) && proto.value === null) return;
      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA008',
          node,
          message:
            `\`Object.setPrototypeOf(${target}, …)\` gives the sandbox global a host-realm ` +
            'prototype.',
          details: BRIDGE_DETAILS,
        }),
      );
      return;
    }

    const sources = call.arguments.slice(1);
    const leaking = sources.filter((source) => !isPrimitiveOnlyObject(source));
    if (leaking.length === 0) return;
    findings.push(
      createFinding(ctx, {
        ruleId: 'NSA008',
        node,
        message:
          `\`Object.assign(${target}, …)\` copies host-realm properties onto the sandbox ` +
          'global; every function or object copied across is a bridge.',
        details: BRIDGE_DETAILS,
      }),
    );
  });

  for (const literal of contextObjectLiterals(ctx)) {
    for (const member of (literal as ObjectExpression).properties) {
      if (member.type !== 'Property') continue;
      const property = member as Property;
      const key = propertyName(property.key, property.computed);
      const valuePath = memberPath(property.value);
      const isProtoKey = key === '__proto__';
      const isPrototypeValue = valuePath !== null && valuePath[valuePath.length - 1] === 'prototype';
      if (!isProtoKey && !isPrototypeValue) continue;

      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA008',
          node: property,
          message: isProtoKey
            ? 'The context object sets `__proto__`, so the sandbox global inherits from a ' +
              'host-realm object.'
            : `The context object exposes \`${valuePath?.join('.') ?? 'a prototype'}\` on the ` +
              'sandbox global.',
          details: BRIDGE_DETAILS,
        }),
      );
    }
  }

  return findings;
}
