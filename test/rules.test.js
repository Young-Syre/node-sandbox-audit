import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { test } from 'node:test';

import { RULES, RULE_IDS, scanSource } from '../dist/index.js';
import { SAFE_DIR, VULNERABLE_DIR, findingsFor, ruleIdsFor, scanFixture } from './helpers.js';

/**
 * Every rule is pinned to the fixtures it must fire on and the fixtures it must stay quiet on.
 * The quiet half is the half that matters: a rule that cannot be silenced is a rule nobody runs.
 */
const EXPECTATIONS = {
  NSA001: {
    fires: ['denylist-missing-vm.js', 'denylist-node-prefix-bypass.js', 'denylist-usage-inferred.js'],
    quiet: ['allowlist-loader.js', 'allowlist-usage-inferred.js', 'data-only-context.js'],
  },
  NSA002: {
    fires: ['denylist-missing-vm.js', 'denylist-node-prefix-bypass.js', 'denylist-usage-inferred.js'],
    quiet: ['allowlist-loader.js', 'allowlist-usage-inferred.js'],
  },
  NSA003: {
    fires: ['empty-context.js', 'leaky-context.cjs'],
    quiet: ['data-only-context.js', 'data-only-sandbox.js', 'timeouts-everywhere.js'],
  },
  NSA004: {
    fires: ['run-in-this-context.js', 'compile-function-host-realm.js'],
    quiet: ['compile-function-with-context.js', 'data-only-context.js'],
  },
  NSA005: {
    fires: ['missing-timeout.js'],
    quiet: ['timeouts-everywhere.js', 'data-only-context.js'],
  },
  NSA006: {
    fires: ['vm2-sandbox.js'],
    quiet: ['isolated-vm-copy.js'],
  },
  NSA007: {
    fires: ['isolated-vm-reference.js'],
    quiet: ['isolated-vm-copy.js'],
  },
  NSA008: {
    fires: ['prototype-bridge.js', 'context-proto-key.js'],
    quiet: ['data-only-sandbox.js', 'data-only-context.js'],
  },
};

test('every rule has an expectation entry', () => {
  assert.deepEqual(Object.keys(EXPECTATIONS).sort(), [...RULE_IDS].sort());
});

for (const [ruleId, { fires, quiet }] of Object.entries(EXPECTATIONS)) {
  for (const fixture of fires) {
    test(`${ruleId} fires on vulnerable/${fixture}`, () => {
      const findings = findingsFor('vulnerable', fixture, ruleId);
      assert.ok(findings.length > 0, `expected ${ruleId} to fire on ${fixture}`);
      for (const finding of findings) {
        assert.equal(finding.severity, RULES[ruleId].severity);
        assert.equal(finding.ruleName, RULES[ruleId].name);
        assert.ok(finding.start.line >= 1, 'finding has a real line number');
        assert.ok(finding.start.column >= 1, 'finding has a real column number');
        assert.ok(finding.message.length > 0, 'finding has a message');
        assert.ok(finding.remediation.length > 0, 'finding has remediation');
        assert.ok(finding.codeFrame.includes('^'), 'code frame carries a caret');
        assert.ok(finding.snippet.length > 0, 'finding has a snippet');
      }
    });
  }

  for (const fixture of quiet) {
    test(`${ruleId} does not fire on safe/${fixture}`, () => {
      assert.deepEqual(findingsFor('safe', fixture, ruleId), []);
    });
  }
}

test('no safe fixture produces any finding at all', () => {
  for (const fixture of readdirSync(SAFE_DIR)) {
    assert.deepEqual(
      scanFixture('safe', fixture).map((finding) => `${finding.ruleId} ${finding.message}`),
      [],
      `safe/${fixture} must be clean`,
    );
  }
});

test('every vulnerable fixture produces at least one finding', () => {
  for (const fixture of readdirSync(VULNERABLE_DIR)) {
    assert.ok(scanFixture('vulnerable', fixture).length > 0, `vulnerable/${fixture} must report`);
  }
});

test('NSA001 names the realm-escape modules that are reachable', () => {
  const [finding] = findingsFor('vulnerable', 'denylist-missing-vm.js', 'NSA001');
  assert.ok(finding.message.includes('`vm`'), 'vm is named as reachable');
  assert.ok(finding.message.includes('`worker_threads`') === false, 'blocked modules are not named');
  assert.ok(
    finding.details.some((detail) => detail.includes('runInThisContext')),
    'the escape chain is spelled out',
  );
  assert.ok(
    finding.details.some((detail) => detail.startsWith('module (evaluation)')),
    'node:module is reported as an evaluation escape',
  );
  assert.ok(
    finding.details.some((detail) => detail.startsWith('v8 (host-object)')),
    'v8 is reported as a host-object escape',
  );
});

test('NSA001 reports the node: prefix bypass separately from the missing escapes', () => {
  const findings = findingsFor('vulnerable', 'denylist-node-prefix-bypass.js', 'NSA001');
  assert.equal(findings.length, 1, 'a list naming every escape only has the prefix gap');
  const [finding] = findings;
  assert.ok(finding.message.includes('one of their two spellings'));
  assert.ok(finding.details.some((detail) => detail.includes('`node:vm` is not')));
});

test('NSA001 anchors the prefix finding on the first offending entry', () => {
  const [prefixFinding] = findingsFor('vulnerable', 'denylist-node-prefix-bypass.js', 'NSA001');
  assert.equal(prefixFinding.snippet, "'vm'");
});

test('NSA002 says when deny intent was inferred from usage rather than naming', () => {
  const [inferred] = findingsFor('vulnerable', 'denylist-usage-inferred.js', 'NSA002');
  assert.ok(inferred.message.includes('inferred from the polarity'));

  const [named] = findingsFor('vulnerable', 'denylist-missing-vm.js', 'NSA002');
  assert.ok(named.message.includes('inferred from the polarity') === false);
});

test('NSA003 credits codeGeneration.strings:false and drops the severity', () => {
  // webpack's magic-comment parser is the real-world shape: an empty context,
  // created with compilation switched off. The context is still not a boundary,
  // so the finding stands -- but the escape the default message describes is
  // already closed, so neither the wording nor the severity should claim it.
  const guarded = scanSource(
    'const vm = require("vm");\n' +
      'module.exports = () => vm.createContext(undefined, {\n' +
      '  name: "parser",\n' +
      '  codeGeneration: { strings: false, wasm: false },\n' +
      '});\n',
    'guarded.js',
  ).filter((finding) => finding.ruleId === 'NSA003');

  assert.equal(guarded.length, 1, 'the context is still reported');
  assert.equal(guarded[0].severity, 'low', 'but not at the rule default of high');
  assert.ok(guarded[0].message.includes('codeGeneration.strings: false'));
  assert.ok(guarded[0].message.includes('not because this line is exploitable'));
  assert.ok(guarded[0].details.some((d) => d.includes('throw inside the')));
  assert.ok(
    guarded[0].details.some((d) => d.includes('codeGeneration.wasm')),
    'the remaining surface is still named',
  );

  // The mitigation must be read from this call, not from the file.
  const unguarded = scanSource(
    'const vm = require("vm");\n' +
      'const a = vm.createContext(undefined, { codeGeneration: { strings: false } });\n' +
      'const b = vm.createContext({});\n',
    'mixed.js',
  ).filter((finding) => finding.ruleId === 'NSA003');

  assert.equal(unguarded.length, 2);
  assert.deepEqual(
    unguarded.map((finding) => finding.severity),
    ['low', 'high'],
  );

  // strings:true is not a mitigation.
  const enabled = scanSource(
    'const vm = require("vm");\n' +
      'vm.createContext({}, { codeGeneration: { strings: true } });\n',
    'enabled.js',
  ).filter((finding) => finding.ruleId === 'NSA003');
  assert.equal(enabled.length, 1);
  assert.equal(enabled[0].severity, 'high');
});

test('NSA003 distinguishes an empty context from a leaky one', () => {
  const [empty] = findingsFor('vulnerable', 'empty-context.js', 'NSA003');
  assert.ok(empty.message.includes('the sandbox global starts empty'));

  const [leaky] = findingsFor('vulnerable', 'leaky-context.cjs', 'NSA003');
  assert.ok(leaky.message.includes('leaks 5 host value(s)'));
  for (const name of ['`require`', '`process`', '`Buffer`']) {
    assert.ok(
      leaky.details.some((detail) => detail.startsWith(name)),
      `${name} is reported as a leak`,
    );
  }
  assert.ok(
    leaky.details.some((detail) => detail.includes('createHash')),
    'an imported host function is reported',
  );
  assert.ok(
    leaky.details.some((detail) => detail.includes('auditLog')),
    'a locally defined host function is reported',
  );
});

test('NSA004 covers both the vm namespace call and the compiled-script method', () => {
  const findings = findingsFor('vulnerable', 'run-in-this-context.js', 'NSA004');
  assert.equal(findings.length, 2);
  const kinds = findings.map((finding) => finding.message.split('`')[1]);
  assert.deepEqual(kinds.sort(), ['script.runInThisContext', 'vm.runInThisContext']);
});

test('NSA004 flags compileFunction only when parsingContext is absent', () => {
  const [finding] = findingsFor('vulnerable', 'compile-function-host-realm.js', 'NSA004');
  assert.ok(finding.message.includes('vm.compileFunction'));
  assert.ok(finding.message.includes('parsingContext'));
});

test('NSA005 reports each run site that omits a timeout', () => {
  const findings = findingsFor('vulnerable', 'missing-timeout.js', 'NSA005');
  assert.equal(findings.length, 2);
  const kinds = findings.map((finding) => finding.message.split('`')[1]).sort();
  assert.deepEqual(kinds, ['script.runInContext', 'vm.runInNewContext']);
});

test('NSA005 reports module.evaluate without a timeout', () => {
  const findings = findingsFor('vulnerable', 'denylist-missing-vm.js', 'NSA005');
  assert.equal(findings.length, 1);
  assert.ok(findings[0].message.includes('module.evaluate'));
});

test('NSA006 names the specifier and how it was loaded', () => {
  const [finding] = findingsFor('vulnerable', 'vm2-sandbox.js', 'NSA006');
  assert.ok(finding.message.includes('`vm2` is imported here'));
});

test('NSA007 reports both the Reference and the copy:false transfer', () => {
  const findings = findingsFor('vulnerable', 'isolated-vm-reference.js', 'NSA007');
  assert.equal(findings.length, 2);
  assert.ok(findings.some((finding) => finding.message.includes('new ivm.Reference(readSecret)')));
  assert.ok(findings.some((finding) => finding.message.includes('copy: false')));
});

test('NSA008 reports prototype, host-global and Object.assign bridges', () => {
  const findings = findingsFor('vulnerable', 'prototype-bridge.js', 'NSA008');
  assert.equal(findings.length, 3);
  assert.ok(findings.some((finding) => finding.message.includes('RequestHelper.prototype')));
  assert.ok(findings.some((finding) => finding.message.includes('`sandbox.Buffer`')));
  assert.ok(findings.some((finding) => finding.message.includes('Object.assign(sandbox')));
});

test('NSA008 reports a __proto__ key on a context object literal', () => {
  const [finding] = findingsFor('vulnerable', 'context-proto-key.js', 'NSA008');
  assert.ok(finding.message.includes('__proto__'));
  assert.equal(finding.start.line, 4);
});

test('NSA003 and NSA008 do not both report the same __proto__ property', () => {
  assert.deepEqual(ruleIdsFor('vulnerable', 'context-proto-key.js'), ['NSA008']);
});

test('the flagship fixture reproduces the full finding set for the bug class', () => {
  assert.deepEqual(ruleIdsFor('vulnerable', 'denylist-missing-vm.js').sort(), [
    'NSA001',
    'NSA001',
    'NSA002',
    'NSA003',
    'NSA005',
  ]);
});
