import ivm from 'isolated-vm';

export async function run(code, input) {
  const isolate = new ivm.Isolate({ memoryLimit: 16 });
  const context = await isolate.createContext();

  await context.global.set('input', new ivm.ExternalCopy(input).copyInto({ release: true }));

  const script = await isolate.compileScript(code);
  const result = await script.run(context, { timeout: 100, copy: true });

  isolate.dispose();
  return result;
}
