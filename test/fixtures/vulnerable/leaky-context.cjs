'use strict';

const vm = require('node:vm');
const { createHash } = require('node:crypto');

function auditLog(message) {
  process.stderr.write(`${message}\n`);
}

exports.run = function run(code) {
  return vm.runInNewContext(
    code,
    { require, process, Buffer, hash: createHash, log: auditLog },
    { timeout: 100 },
  );
};
