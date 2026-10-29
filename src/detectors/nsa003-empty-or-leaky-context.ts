import {
  argAt,
  isBareObjectCreateNull,
  isEmptyObjectLiteral,
  isFunctionish,
  isIdentifier,
  isLiteral,
  isNullishLiteral,
  memberPath,
  propertyName,
  type AstNode,
  type ObjectExpression,
  type Property,
  type SpreadElement,
} from '../ast.js';
import { HOST_GLOBALS, HOST_INTRINSICS } from '../builtins.js';
import type { FileContext } from '../context.js';
import { createFinding } from '../finding.js';
import type { Finding } from '../types.js';
import { vmCalls, type VmCall } from './vmcalls.js';

/**
 * True when the call's options argument sets `codeGeneration.strings` to false.
 *
 * That option makes `eval` and the `Function` constructor throw inside the
 * context, which closes the specific escape this rule's rationale is built on:
 * `value.constructor.constructor("return process")()` has nothing to compile
 * with. The context is still not a security boundary -- a host value handed in
 * afterwards is reachable, `wasm` may still be enabled, and the Node
 * documentation's warning is unconditional -- so the finding stands. It just
 * should not stand at the same severity, and the message should not describe an
 * escape the code has already blocked.
 */
function compilationDisabled(vmCall: VmCall): boolean {
  const options = argAt(vmCall.call.arguments, vmCall.optionsIndex);
  if (options === null || options.type !== 'ObjectExpression') return false;
  for (const property of (options as ObjectExpression).properties) {
    if (property.type !== 'Property') continue;
    if (propertyName(property.key, property.computed) !== 'codeGeneration') continue;
    const value = property.value;
    if (value.type !== 'ObjectExpression') continue;
    for (const inner of (value as ObjectExpression).properties) {
      if (inner.type !== 'Property') continue;
      if (propertyName(inner.key, inner.computed) !== 'strings') continue;
      if (isLiteral(inner.value) && inner.value.value === false) return true;
    }
  }
  return false;
}

const CODEGEN_DISABLED_DETAILS = [
  '`codeGeneration.strings: false` makes `eval` and the `Function` constructor throw inside the ' +
    'context, so the prototype-chain route to compiling host-realm code is closed here.',
  'What remains is everything that does not need to compile: any host object handed in after ' +
    'creation is still reachable through its prototype chain, and `codeGeneration.wasm` is a ' +
    'separate switch. The Node documentation still states that `vm` is not a security mechanism.',
];

const EMPTY_CONTEXT_DETAILS = [
  'An empty context is not an empty realm. Every value the host hands in or reads back out ' +
    'carries a prototype chain, and `value.constructor.constructor("return process")()` compiles ' +
    'in whichever realm owns that chain.',
  'The Node documentation states outright that the `vm` module is not a security mechanism and ' +
    'must not be used to run untrusted code.',
];

/** Properties handled by NSA008 instead, so the two rules do not both report the same node. */
function isPrototypeBridge(property: Property): boolean {
  if (propertyName(property.key, property.computed) === '__proto__') return true;
  const path = memberPath(property.value);
  return path !== null && path[path.length - 1] === 'prototype';
}

function leakReason(ctx: FileContext, property: Property): string | null {
  const key = propertyName(property.key, property.computed) ?? '<computed>';

  if (HOST_GLOBALS.has(key)) {
    return `\`${key}\` is passed straight through, handing guest code the host value by that name.`;
  }
  if (HOST_INTRINSICS.has(key)) {
    return `\`${key}\` is a host intrinsic; guest code can compile host-realm code with it directly.`;
  }
  if (isFunctionish(property.value)) {
    return (
      `\`${key}\` is a function defined in the host realm. Its \`constructor\` is the host ` +
      '`Function`, so guest code can reach the host realm through it.'
    );
  }
  if (ctx.isHostValue(property.value)) {
    const path = memberPath(property.value);
    const shown = path === null ? 'a host value' : `\`${path.join('.')}\``;
    return `\`${key}\` is bound to ${shown}, an object created in the host realm.`;
  }
  return null;
}

export function detect(ctx: FileContext): Finding[] {
  const findings: Finding[] = [];

  for (const vmCall of vmCalls(ctx)) {
    if (!vmCall.contextIsPlainObject) continue;
    const contextArg = argAt(vmCall.call.arguments, vmCall.contextIndex);

    if (
      contextArg === null ||
      isNullishLiteral(contextArg) ||
      isEmptyObjectLiteral(contextArg) ||
      isBareObjectCreateNull(contextArg)
    ) {
      const shape =
        contextArg === null
          ? 'no context object at all'
          : `\`${ctx.source.slice(contextArg.start, contextArg.end)}\``;
      const guarded = compilationDisabled(vmCall);
      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA003',
          node: contextArg ?? vmCall.call,
          message: guarded
            ? `\`${vmCall.kind}\` is given ${shape}, so the sandbox global starts empty — but ` +
              'this call also sets `codeGeneration.strings: false`, which blocks the realm-compile ' +
              'escape. Reported so the context is accounted for, not because this line is ' +
              'exploitable as written.'
            : `\`${vmCall.kind}\` is given ${shape}, so the sandbox global starts empty. An empty ` +
              'global is not a boundary — it only removes the obvious names.',
          details: guarded ? CODEGEN_DISABLED_DETAILS : EMPTY_CONTEXT_DETAILS,
          ...(guarded ? { severity: 'low' as const } : {}),
        }),
      );
      continue;
    }

    if (isIdentifier(contextArg) && HOST_GLOBALS.has(contextArg.name)) {
      findings.push(
        createFinding(ctx, {
          ruleId: 'NSA003',
          node: contextArg,
          message:
            `\`${vmCall.kind}\` is given the host value \`${contextArg.name}\` as the sandbox ` +
            'global, so guest code runs with the host global object in scope.',
          details: EMPTY_CONTEXT_DETAILS,
        }),
      );
      continue;
    }

    if (contextArg.type !== 'ObjectExpression') continue;

    const reasons: string[] = [];
    for (const member of (contextArg as ObjectExpression).properties) {
      if (member.type === 'SpreadElement') {
        const spread = member as SpreadElement;
        const path = memberPath(spread.argument);
        reasons.push(
          `every own property of ${path === null ? 'the spread object' : `\`${path.join('.')}\``} ` +
            'is copied onto the sandbox global, including host-realm objects.',
        );
        continue;
      }
      const property = member as Property;
      if (isPrototypeBridge(property)) continue;
      const reason = leakReason(ctx, property);
      if (reason !== null) reasons.push(reason);
    }

    if (reasons.length === 0) continue;

    findings.push(
      createFinding(ctx, {
        ruleId: 'NSA003',
        node: contextArg,
        message:
          `The context object passed to \`${vmCall.kind}\` leaks ${reasons.length} host value(s) ` +
          'into the sandbox global.',
        details: reasons,
      }),
    );
  }

  return findings;
}

/** Context object literals, exported so NSA008 can inspect the same nodes. */
export function contextObjectLiterals(ctx: FileContext): AstNode[] {
  const literals: AstNode[] = [];
  for (const vmCall of vmCalls(ctx)) {
    if (!vmCall.contextIsPlainObject) continue;
    const contextArg = argAt(vmCall.call.arguments, vmCall.contextIndex);
    if (contextArg?.type === 'ObjectExpression') literals.push(contextArg);
  }
  return literals;
}
