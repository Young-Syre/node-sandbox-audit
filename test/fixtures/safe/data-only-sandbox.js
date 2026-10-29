import vm from 'node:vm';

const sandbox = { requestId: 'abc123', retries: 3 };
vm.createContext(sandbox);
Object.assign(sandbox, { locale: 'en-GB' });

export const run = (code) => vm.runInContext(code, sandbox, { timeout: 20 });
