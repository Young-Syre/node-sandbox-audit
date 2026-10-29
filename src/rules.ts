import type { Rule, RuleId } from './types.js';

const HELP_BASE = 'https://github.com/Young-Syre/node-sandbox-audit#rules';

export const RULES: Readonly<Record<RuleId, Rule>> = {
  NSA001: {
    id: 'NSA001',
    name: 'denylist-missing-realm-escape',
    severity: 'critical',
    summary:
      'A module denylist omits a realm-escape module, or omits one of the two spellings ' +
      '(`fs` / `node:fs`) of a module it blocks.',
    rationale:
      'Any module that can evaluate code in another realm, or hand back an object created in ' +
      'another realm, is transitively equivalent to every module the denylist blocks. Reaching ' +
      'one of them defeats the whole list in a single step.',
    remediation:
      'Replace the denylist with an allowlist of the exact specifiers the sandbox needs, and ' +
      'normalise the specifier (strip a leading `node:`) before comparing.',
    helpUri: `${HELP_BASE}`,
  },
  NSA002: {
    id: 'NSA002',
    name: 'denylist-instead-of-allowlist',
    severity: 'high',
    summary: 'Import filtering is expressed as a set of blocked modules rather than permitted ones.',
    rationale:
      'A denylist is only correct if it is complete, and the set of reachable capabilities grows ' +
      'with every Node release and every transitive re-export. An allowlist fails closed; a ' +
      'denylist fails open.',
    remediation:
      'Invert the check: resolve the specifier, compare it against an explicit allowlist, and ' +
      'reject everything else.',
    helpUri: `${HELP_BASE}`,
  },
  NSA003: {
    id: 'NSA003',
    name: 'empty-or-leaky-context',
    severity: 'high',
    summary:
      'A `vm` context is created empty, or is seeded with host values such as `require`, ' +
      '`process`, `globalThis`, `Buffer`, or a host function.',
    rationale:
      'An empty context is not an empty realm: every object the host passes in or receives back ' +
      'carries a prototype chain, and `obj.constructor.constructor` reaches the host `Function`. ' +
      'Seeding the context with a host value makes that reachable directly.',
    remediation:
      'Do not treat `vm` as a boundary. If untrusted code must run, use a separate process or ' +
      '`isolated-vm`, and transfer only copied primitives across the boundary.',
    helpUri: `${HELP_BASE}`,
  },
  NSA004: {
    id: 'NSA004',
    name: 'run-in-this-context',
    severity: 'critical',
    summary:
      'Code is compiled or run with no contextified object — `vm.runInThisContext`, ' +
      '`script.runInThisContext`, or `vm.compileFunction` without `parsingContext`.',
    rationale:
      'These APIs evaluate in the calling realm by definition. The global scope of the evaluated ' +
      'code is the host global scope, so there is no sandbox at all, only the appearance of one.',
    remediation:
      'Pass a contextified object: `vm.runInContext(code, context, { timeout })`, or ' +
      '`vm.compileFunction(code, params, { parsingContext: context })`.',
    helpUri: `${HELP_BASE}`,
  },
  NSA005: {
    id: 'NSA005',
    name: 'missing-timeout',
    severity: 'medium',
    summary: 'A `vm` run or module evaluation has no `timeout` option.',
    rationale:
      'Without a timeout, `while (true) {}` in guest code hangs the thread that called it. On a ' +
      'single-threaded server that is a full denial of service from one request.',
    remediation:
      'Pass `{ timeout: <ms> }`. Note that a timeout does not stop a `SharedArrayBuffer` spin or ' +
      'an allocation bomb, so also cap memory and prefer running guest code off the main thread.',
    helpUri: `${HELP_BASE}`,
  },
  NSA006: {
    id: 'NSA006',
    name: 'vm2-usage',
    severity: 'high',
    summary: 'The `vm2` package is imported.',
    rationale:
      'vm2 is discontinued. Its maintainer withdrew it after a series of sandbox-escape reports ' +
      'that it could not fix structurally, and its README now states that it should not be used ' +
      'to run untrusted code.',
    remediation:
      'Migrate to `isolated-vm`, which gives a genuinely separate V8 isolate and heap, or run ' +
      'guest code in a separate process with an OS-level sandbox.',
    helpUri: `${HELP_BASE}`,
  },
  NSA007: {
    id: 'NSA007',
    name: 'isolated-vm-reference-leak',
    severity: 'high',
    summary:
      'An `isolated-vm` boundary is crossed by reference — `new ivm.Reference(...)` or a transfer ' +
      'option of `copy: false` / `reference: true`.',
    rationale:
      'isolated-vm is sound because the two isolates share no heap. A `Reference` reintroduces the ' +
      'bridge: guest code holding a reference to a host function can call it, and `apply` on a ' +
      'host function is enough to execute host-realm code.',
    remediation:
      'Transfer copies instead: `new ivm.ExternalCopy(value).copyInto()`. If the guest must call ' +
      'host logic, expose a narrow `ivm.Callback` whose arguments and return value are copied, ' +
      'and validate them on the host side.',
    helpUri: `${HELP_BASE}`,
  },
  NSA008: {
    id: 'NSA008',
    name: 'prototype-bridge',
    severity: 'critical',
    summary:
      'A host object, host function, or prototype is attached to the sandbox global, via property ' +
      'assignment, `Object.assign`, `Object.setPrototypeOf`, or a `__proto__` key.',
    rationale:
      'Any host-realm object reachable from guest code is a bridge: ' +
      '`this.constructor.constructor("return process")()` walks from the object to the host ' +
      '`Function` constructor and compiles arbitrary code in the host realm.',
    remediation:
      'Attach only primitives, or structured clones produced in the guest realm. Never place a ' +
      'host function, class, or prototype on the sandbox global.',
    helpUri: `${HELP_BASE}`,
  },
};

export const RULE_IDS: readonly RuleId[] = Object.keys(RULES) as RuleId[];

export function isRuleId(value: string): value is RuleId {
  return Object.prototype.hasOwnProperty.call(RULES, value);
}
