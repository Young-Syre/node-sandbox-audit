import type { AstNode, CallExpression } from '../ast.js';
import type { FileContext } from '../context.js';

export type VmCallKind =
  | 'vm.createContext'
  | 'vm.runInThisContext'
  | 'vm.runInNewContext'
  | 'vm.runInContext'
  | 'vm.compileFunction'
  | 'script.runInThisContext'
  | 'script.runInNewContext'
  | 'script.runInContext'
  | 'module.evaluate';

export interface VmCall {
  kind: VmCallKind;
  call: CallExpression;
  /** Argument index of the options bag, or -1 when the API takes none. */
  optionsIndex: number;
  /** Argument index of the context/sandbox object, or -1 when the API takes none. */
  contextIndex: number;
  /** Whether the options bag honours `timeout`. */
  supportsTimeout: boolean;
  /** Whether this API evaluates in the calling realm unless given a context. */
  hostRealmByDefault: boolean;
  /** Whether the context argument is a plain object that becomes the new global. */
  contextIsPlainObject: boolean;
}

interface Shape {
  optionsIndex: number;
  contextIndex: number;
  supportsTimeout: boolean;
  hostRealmByDefault: boolean;
  contextIsPlainObject: boolean;
}

const SHAPES: Record<VmCallKind, Shape> = {
  'vm.createContext': {
    optionsIndex: 1,
    contextIndex: 0,
    supportsTimeout: false,
    hostRealmByDefault: false,
    contextIsPlainObject: true,
  },
  'vm.runInThisContext': {
    optionsIndex: 1,
    contextIndex: -1,
    supportsTimeout: true,
    hostRealmByDefault: true,
    contextIsPlainObject: false,
  },
  'vm.runInNewContext': {
    optionsIndex: 2,
    contextIndex: 1,
    supportsTimeout: true,
    hostRealmByDefault: false,
    contextIsPlainObject: true,
  },
  'vm.runInContext': {
    optionsIndex: 2,
    contextIndex: 1,
    supportsTimeout: true,
    hostRealmByDefault: false,
    contextIsPlainObject: false,
  },
  'vm.compileFunction': {
    optionsIndex: 2,
    contextIndex: -1,
    supportsTimeout: false,
    hostRealmByDefault: true,
    contextIsPlainObject: false,
  },
  'script.runInThisContext': {
    optionsIndex: 0,
    contextIndex: -1,
    supportsTimeout: true,
    hostRealmByDefault: true,
    contextIsPlainObject: false,
  },
  'script.runInNewContext': {
    optionsIndex: 1,
    contextIndex: 0,
    supportsTimeout: true,
    hostRealmByDefault: false,
    contextIsPlainObject: true,
  },
  'script.runInContext': {
    optionsIndex: 1,
    contextIndex: 0,
    supportsTimeout: true,
    hostRealmByDefault: false,
    contextIsPlainObject: false,
  },
  'module.evaluate': {
    optionsIndex: 0,
    contextIndex: -1,
    supportsTimeout: true,
    hostRealmByDefault: false,
    contextIsPlainObject: false,
  },
};

const VM_MEMBERS = new Set([
  'createContext',
  'runInThisContext',
  'runInNewContext',
  'runInContext',
  'compileFunction',
]);

const SCRIPT_METHODS = new Set(['runInThisContext', 'runInNewContext', 'runInContext']);

function build(kind: VmCallKind, call: CallExpression): VmCall {
  return { kind, call, ...SHAPES[kind] };
}

/** Identifies a `vm` API call, whether reached through the namespace, a destructured binding, or a tracked `vm.Script` / `vm.SourceTextModule` variable. */
export function classifyVmCall(ctx: FileContext, node: AstNode): VmCall | null {
  if (node.type !== 'CallExpression') return null;
  const call = node as CallExpression;

  const identity = ctx.resolveCallee(call.callee);
  if (identity?.module === 'vm' && VM_MEMBERS.has(identity.member)) {
    return build(`vm.${identity.member}` as VmCallKind, call);
  }

  const scriptMethod = ctx.resolveScriptMethod(call);
  if (scriptMethod === null) return null;
  if (scriptMethod.onModule) {
    return scriptMethod.method === 'evaluate' ? build('module.evaluate', call) : null;
  }
  if (SCRIPT_METHODS.has(scriptMethod.method)) {
    return build(`script.${scriptMethod.method}` as VmCallKind, call);
  }
  return null;
}

/** Every `vm` API call in the file, in source order. */
export function vmCalls(ctx: FileContext): VmCall[] {
  const calls: VmCall[] = [];
  ctx.walk((node) => {
    const classified = classifyVmCall(ctx, node);
    if (classified !== null) calls.push(classified);
  });
  return calls;
}
