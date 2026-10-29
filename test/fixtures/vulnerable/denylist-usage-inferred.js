// The binding name says nothing about intent; the polarity of the membership test does.
const modules = ['child_process', 'fs', 'net'];

export function loadModule(specifier) {
  if (modules.includes(specifier)) {
    throw new Error(`blocked: ${specifier}`);
  }
  return import(specifier);
}
