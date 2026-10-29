import vm from 'node:vm';

class RequestHelper {
  constructor(id) {
    this.id = id;
  }

  describe() {
    return `request ${this.id}`;
  }
}

const sandbox = { requestId: 'r-1' };
vm.createContext(sandbox);

sandbox.Helper = RequestHelper.prototype;
sandbox.Buffer = Buffer;
Object.assign(sandbox, { helpers: new RequestHelper('r-1') });

export const run = (code) => vm.runInContext(code, sandbox, { timeout: 50 });
