import vm from 'node:vm';

const script = new vm.Script('seed + 1', { filename: 'guest.js' });
const context = vm.createContext({ seed: 7 });

export function evaluate() {
  return script.runInContext(context, { timeout: 25, breakOnSigint: true });
}

export function evaluateOnce(code) {
  return vm.runInNewContext(code, { seed: 7 }, { timeout: 25 });
}
