import vm from 'node:vm';

export function evaluate(expression) {
  return vm.runInThisContext(expression, { timeout: 100, filename: 'guest.js' });
}

export function evaluateCompiled(expression) {
  const script = new vm.Script(expression, { filename: 'guest.js' });
  return script.runInThisContext({ timeout: 100 });
}
