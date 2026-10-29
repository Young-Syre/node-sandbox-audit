import vm from 'node:vm';

const context = vm.createContext({ answer: 42, label: 'demo', enabled: true });

export function run(code) {
  return vm.runInContext(code, context, { timeout: 50, displayErrors: false });
}
