// Same ambiguous binding name as the vulnerable counterpart; the negated membership test is
// what makes this an allowlist.
const modules = ['path', 'url', 'node:path', 'node:url'];

export function loadModule(specifier) {
  if (!modules.includes(specifier)) {
    throw new Error(`not permitted: ${specifier}`);
  }
  return import(specifier);
}
