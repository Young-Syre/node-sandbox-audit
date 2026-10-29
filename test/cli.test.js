import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

import { RULE_IDS } from '../dist/index.js';
import { CLI, PROJECT_ROOT, SAFE_DIR, VULNERABLE_DIR, fixturePath } from './helpers.js';

function run(args) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  assert.equal(result.error, undefined);
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test('--version prints the version and exits 0', () => {
  const { status, stdout } = run(['--version']);
  assert.equal(status, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('--help documents every format and exits 0', () => {
  const { status, stdout } = run(['--help']);
  assert.equal(status, 0);
  for (const fragment of ['scan <paths...>', '--format', '--severity-threshold', '--exit-code']) {
    assert.ok(stdout.includes(fragment), `help mentions ${fragment}`);
  }
});

test('running with no arguments prints usage and exits 2', () => {
  const { status, stdout } = run([]);
  assert.equal(status, 2);
  assert.ok(stdout.includes('Usage:'));
});

test('scan with no paths exits 2', () => {
  const { status, stderr } = run(['scan']);
  assert.equal(status, 2);
  assert.ok(stderr.includes('requires at least one path'));
});

test('an unknown option exits 2 without scanning', () => {
  const { status, stderr } = run(['scan', VULNERABLE_DIR, '--nope']);
  assert.equal(status, 2);
  assert.ok(stderr.includes("unknown option '--nope'"));
});

test('an unknown rule id is rejected', () => {
  const { status, stderr } = run(['scan', VULNERABLE_DIR, '--rule', 'NSA999']);
  assert.equal(status, 2);
  assert.ok(stderr.includes("unknown rule 'NSA999'"));
});

test('an unknown format is rejected', () => {
  const { status, stderr } = run(['scan', VULNERABLE_DIR, '--format', 'yaml']);
  assert.equal(status, 2);
  assert.ok(stderr.includes("unknown format 'yaml'"));
});

test('text format reports the vulnerable fixtures', () => {
  const { status, stdout } = run(['scan', VULNERABLE_DIR]);
  assert.equal(status, 0);
  assert.ok(stdout.includes('NSA001'));
  assert.ok(stdout.includes('^'));
  assert.ok(/\d+ findings \(/.test(stdout));
});

test('json format is parseable and summarises the run', () => {
  const { status, stdout } = run(['scan', VULNERABLE_DIR, '--format', 'json']);
  assert.equal(status, 0);
  const report = JSON.parse(stdout);
  assert.ok(report.summary.findings > 0);
  assert.equal(report.summary.filesScanned, 12);
  assert.ok(report.findings.every((finding) => RULE_IDS.includes(finding.ruleId)));
});

test('sarif format is parseable and carries the required 2.1.0 keys', () => {
  const { status, stdout } = run(['scan', VULNERABLE_DIR, '--format', 'sarif']);
  assert.equal(status, 0);
  const sarif = JSON.parse(stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.$schema.includes('sarif-schema-2.1.0'));
  assert.equal(sarif.runs[0].tool.driver.name, 'node-sandbox-audit');
  assert.ok(sarif.runs[0].results.length > 0);
});

test('--exit-code exits 1 when findings are reported', () => {
  const { status } = run(['scan', VULNERABLE_DIR, '--exit-code']);
  assert.equal(status, 1);
});

test('--exit-code exits 0 on a clean tree', () => {
  const { status, stdout } = run(['scan', SAFE_DIR, '--exit-code']);
  assert.equal(status, 0);
  assert.ok(stdout.includes('No findings.'));
});

test('--rule restricts output to the requested rules', () => {
  const { stdout } = run([
    'scan',
    VULNERABLE_DIR,
    '--rule',
    'NSA004,NSA006',
    '--format',
    'json',
  ]);
  const report = JSON.parse(stdout);
  assert.deepEqual(Object.keys(report.summary.byRule).sort(), ['NSA004', 'NSA006']);
});

test('--ignore-rule removes a rule from the run', () => {
  const { stdout } = run(['scan', VULNERABLE_DIR, '--ignore-rule=NSA001', '--format', 'json']);
  const report = JSON.parse(stdout);
  assert.equal('NSA001' in report.summary.byRule, false);
  assert.ok(report.summary.findings > 0);
});

test('--severity-threshold filters by severity', () => {
  const { stdout } = run([
    'scan',
    VULNERABLE_DIR,
    '--severity-threshold',
    'critical',
    '--format',
    'json',
  ]);
  const report = JSON.parse(stdout);
  assert.equal(report.summary.bySeverity.high, 0);
  assert.equal(report.summary.bySeverity.medium, 0);
  assert.ok(report.summary.bySeverity.critical > 0);
});

test('--severity-threshold also governs the --exit-code decision', () => {
  const path = fixturePath('vulnerable', 'missing-timeout.js');
  const low = run(['scan', path, '--exit-code']);
  const high = run(['scan', path, '--exit-code', '--severity-threshold', 'high']);
  assert.equal(low.status, 1, 'medium findings fail the build at the default threshold');
  assert.equal(high.status, 0, 'and are ignored above it');
});

test('parse failures are warned about on stderr and leave stdout machine-readable', () => {
  const { status, stdout, stderr } = run([
    'scan',
    fixturePath('vulnerable', 'denylist-missing-vm.js'),
    'test/fixtures/nope.js',
    '--format',
    'json',
  ]);
  assert.equal(status, 0);
  assert.ok(stderr.includes('warning: test/fixtures/nope.js'));
  assert.ok(JSON.parse(stdout).summary.findings > 0);
});

test('the rules command lists every rule', () => {
  const { status, stdout } = run(['rules']);
  assert.equal(status, 0);
  for (const ruleId of RULE_IDS) assert.ok(stdout.includes(ruleId));
});

test('the rules command emits json on request', () => {
  const { stdout } = run(['rules', '--format', 'json']);
  const rules = JSON.parse(stdout);
  assert.equal(rules.length, RULE_IDS.length);
  assert.ok(rules.every((rule) => typeof rule.rationale === 'string' && rule.rationale.length > 0));
});

test('an unknown command exits 2', () => {
  const { status, stderr } = run(['audit', VULNERABLE_DIR]);
  assert.equal(status, 2);
  assert.ok(stderr.includes("unknown command 'audit'"));
});

test('stdout closing early is not an error', () => {
  const result = spawnSync('sh', ['-c', `"${process.execPath}" "${CLI}" rules | head -1`], {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  assert.ok(result.stderr.includes('EPIPE') === false, result.stderr);
  assert.ok(result.stdout.startsWith('NSA001'));
});
