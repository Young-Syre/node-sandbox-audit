import { createRequire } from 'node:module';

const load = createRequire(import.meta.url);

const ALLOWED_MODULES = new Set(['path', 'url', 'querystring']);

function normalise(specifier) {
  return specifier.startsWith('node:') ? specifier.slice(5) : specifier;
}

export function guardedRequire(specifier) {
  const name = normalise(specifier);
  if (!ALLOWED_MODULES.has(name)) {
    throw new Error(`module ${specifier} is not on the allowlist`);
  }
  return load(name);
}
