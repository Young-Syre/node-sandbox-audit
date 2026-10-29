// The shape this tool was written for: a REPL kernel that evaluates untrusted source with
// vm.SourceTextModule and guards imports with a short denylist of "dangerous" modules.
//
// `node:vm` is not on the list, so guest code runs:
//     const vm = await import('node:vm');
//     const host = vm.runInThisContext('process');
//     host.mainModule.require('child_process').execSync('id');
import vm from 'node:vm';

const BLOCKED_MODULES = new Set(['process', 'child_process', 'worker_threads']);

async function link(specifier, referencingModule) {
  if (BLOCKED_MODULES.has(specifier)) {
    throw new Error(`import of ${specifier} is not allowed`);
  }
  const resolved = await import(specifier);
  const exported = Object.keys(resolved);
  return new vm.SyntheticModule(
    exported,
    function bind() {
      for (const name of exported) {
        this.setExport(name, resolved[name]);
      }
    },
    { context: referencingModule.context },
  );
}

export async function evaluate(source) {
  const context = vm.createContext({});
  const guest = new vm.SourceTextModule(source, { context, identifier: 'guest.mjs' });
  await guest.link(link);
  return guest.evaluate();
}
