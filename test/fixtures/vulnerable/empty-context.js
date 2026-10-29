import vm from 'node:vm';

const context = vm.createContext({});

export function run(code) {
  return vm.runInContext(code, context, { timeout: 50 });
}
