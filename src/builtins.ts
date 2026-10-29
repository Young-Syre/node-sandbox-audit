import { builtinModules } from 'node:module';

/**
 * How reaching a module defeats a denylist.
 *
 * - `evaluation`: the module can compile or run code in a realm other than the sandbox's,
 *   which means guest code can obtain a fresh, unrestricted global object.
 * - `host-object`: the module hands back an object constructed in the host realm. That is
 *   sufficient on its own, because `value.constructor.constructor('return process')()`
 *   walks from any host object to the host `Function` constructor.
 */
export type EscapeKind = 'evaluation' | 'host-object';

export interface RealmEscapeModule {
  name: string;
  kind: EscapeKind;
  /** Concrete mechanism, stated as the call an attacker makes. */
  mechanism: string;
}

export const REALM_ESCAPE_MODULES: readonly RealmEscapeModule[] = [
  {
    name: 'vm',
    kind: 'evaluation',
    mechanism:
      '`vm.runInThisContext(src)` compiles src in the *calling* realm, where `process` and ' +
      '`require` are in scope. `process.mainModule.require` then loads any module at all.',
  },
  {
    name: 'module',
    kind: 'evaluation',
    mechanism:
      '`module.createRequire(path)` returns a fully functional `require` for any file on disk, ' +
      'bypassing whatever loader hook the denylist is attached to.',
  },
  {
    name: 'repl',
    kind: 'evaluation',
    mechanism:
      '`repl.start({ useGlobal: true })` attaches an evaluator that runs input against the host ' +
      'global object.',
  },
  {
    name: 'inspector',
    kind: 'evaluation',
    mechanism:
      "`new inspector.Session().post('Runtime.evaluate', { expression })` evaluates in the " +
      'inspected (host) context; `inspector.open()` additionally exposes a debugger port.',
  },
  {
    name: 'worker_threads',
    kind: 'evaluation',
    mechanism:
      '`new Worker(src, { eval: true })` starts a thread with an unrestricted module loader, and ' +
      '`SharedArrayBuffer` gives shared memory back to the parent.',
  },
  {
    name: 'async_hooks',
    kind: 'host-object',
    mechanism:
      '`async_hooks.executionAsyncResource()` returns the host-realm resource object for the ' +
      'current execution, which is a usable constructor bridge.',
  },
  {
    name: 'perf_hooks',
    kind: 'host-object',
    mechanism:
      '`perf_hooks.performance.nodeTiming` and `PerformanceObserver` entries are host-realm ' +
      'objects, which is a usable constructor bridge.',
  },
  {
    name: 'trace_events',
    kind: 'host-object',
    mechanism:
      '`trace_events.createTracing({ categories })` returns a host-realm `Tracing` object, which ' +
      'is a usable constructor bridge.',
  },
  {
    name: 'v8',
    kind: 'host-object',
    mechanism:
      "`v8.setFlagsFromString('--allow-natives-syntax')` changes how code compiled afterwards is " +
      'parsed, and `v8.deserialize` constructs host-realm objects from attacker-controlled bytes.',
  },
];

export const REALM_ESCAPE_NAMES: readonly string[] = REALM_ESCAPE_MODULES.map((m) => m.name);

const REALM_ESCAPE_BY_NAME = new Map(REALM_ESCAPE_MODULES.map((m) => [m.name, m]));

export function realmEscape(name: string): RealmEscapeModule | undefined {
  return REALM_ESCAPE_BY_NAME.get(stripNodePrefix(name));
}

/**
 * Node builtin specifiers, taken from the running Node so the list does not go stale,
 * unioned with the realm-escape names so detection does not depend on the host version.
 */
export const NODE_BUILTINS: ReadonlySet<string> = new Set<string>([
  ...builtinModules.map(stripNodePrefix),
  ...REALM_ESCAPE_NAMES,
]);

export function stripNodePrefix(specifier: string): string {
  return specifier.startsWith('node:') ? specifier.slice(5) : specifier;
}

export function isNodeBuiltin(specifier: string): boolean {
  return NODE_BUILTINS.has(stripNodePrefix(specifier));
}

/** Host values that must never be reachable from guest code. */
export const HOST_GLOBALS: ReadonlySet<string> = new Set([
  'require',
  'process',
  'global',
  'globalThis',
  'Buffer',
  'module',
  'exports',
  '__dirname',
  '__filename',
]);

/** Intrinsics whose presence on a sandbox global is a direct bridge to host-realm `Function`. */
export const HOST_INTRINSICS: ReadonlySet<string> = new Set([
  'Function',
  'eval',
  'Reflect',
  'Proxy',
  'WebAssembly',
  'import',
]);
