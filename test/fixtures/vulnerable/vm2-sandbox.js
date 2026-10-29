import { VM } from 'vm2';

export function run(code) {
  const sandbox = new VM({ timeout: 100, sandbox: {} });
  return sandbox.run(code);
}
