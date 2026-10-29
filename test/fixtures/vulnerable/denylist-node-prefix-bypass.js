import { createRequire } from 'node:module';

const load = createRequire(import.meta.url);

// Every realm-escape module is listed — but only under its bare name, so `node:vm` walks past.
const DENIED_SPECIFIERS = [
  'vm',
  'module',
  'repl',
  'inspector',
  'worker_threads',
  'async_hooks',
  'perf_hooks',
  'trace_events',
  'v8',
  'fs',
  'child_process',
  'process',
];

export function guardedRequire(specifier) {
  if (DENIED_SPECIFIERS.includes(specifier)) {
    throw new Error(`module ${specifier} is denied`);
  }
  return load(specifier);
}
