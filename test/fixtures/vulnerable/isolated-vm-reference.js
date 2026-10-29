import ivm from 'isolated-vm';

function readSecret(name) {
  return process.env[name];
}

const hostApi = { readSecret };

export async function run(code) {
  const isolate = new ivm.Isolate({ memoryLimit: 32 });
  const context = await isolate.createContext();
  await context.global.set('readSecret', new ivm.Reference(readSecret));
  await context.global.set('host', hostApi, { copy: false });
  const script = await isolate.compileScript(code);
  return script.run(context, { timeout: 100 });
}
