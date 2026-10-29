import vm from 'node:vm';

export function run(code) {
  return vm.runInNewContext(code, { __proto__: globalThis, ready: true }, { timeout: 25 });
}
