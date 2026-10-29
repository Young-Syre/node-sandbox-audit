import { compileFunction } from 'node:vm';

export function build(body) {
  return compileFunction(body, ['payload'], { filename: 'guest.js' });
}
