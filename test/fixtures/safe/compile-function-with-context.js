import { compileFunction, createContext } from 'node:vm';

const context = createContext({ limit: 10 });

export function build(body) {
  return compileFunction(body, ['payload'], { parsingContext: context, filename: 'guest.js' });
}
