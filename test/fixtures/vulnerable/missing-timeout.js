import vm from 'node:vm';

const context = vm.createContext({ attempt: 0 });
const script = new vm.Script('attempt += 1', { filename: 'guest.js' });

export function tick() {
  return script.runInContext(context);
}

export function once(code) {
  return vm.runInNewContext(code, { attempt: 0 });
}
