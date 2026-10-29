import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  RULES,
  RULE_IDS,
  VERSION,
  buildJsonReport,
  buildSarifReport,
  formatSarif,
  formatText,
  scanFiles,
} from '../dist/index.js';
import { PROJECT_ROOT, SAFE_DIR, VULNERABLE_DIR } from './helpers.js';

const findings = scanFiles([VULNERABLE_DIR]);

test('VERSION matches package.json', () => {
  const pkg = JSON.parse(readFileSync(join(PROJECT_ROOT, 'package.json'), 'utf8'));
  assert.equal(VERSION, pkg.version);
});

test('text output carries a code frame, a fix line and a summary', () => {
  const output = formatText(findings, { color: false, filesScanned: 12 });
  assert.ok(output.includes('^'), 'includes a caret row');
  assert.ok(output.includes('fix: '), 'includes remediation');
  assert.ok(/\d+ findings \(.*\) in \d+ files\. 12 files scanned\./.test(output), output.slice(-200));
  assert.ok(output.includes('\u001b[') === false, 'no ANSI escapes when colour is off');
});

test('text output states the rules that fired', () => {
  const output = formatText(findings, { color: false, filesScanned: 12 });
  for (const ruleId of RULE_IDS) {
    assert.ok(output.includes(ruleId), `${ruleId} appears in the report`);
  }
});

test('text output emits ANSI escapes when colour is on', () => {
  const output = formatText(findings, { color: true, filesScanned: 1 });
  assert.ok(output.includes('\u001b[1;31m'), 'critical findings are highlighted');
});

test('text output for a clean scan says so without a breakdown', () => {
  const output = formatText(scanFiles([SAFE_DIR]), { color: false, filesScanned: 7 });
  assert.equal(output, 'No findings. 7 files scanned.');
});

test('json report summarises by severity and by rule', () => {
  const report = buildJsonReport(findings, { filesScanned: 12 });
  assert.equal(report.tool.name, 'node-sandbox-audit');
  assert.equal(report.summary.findings, findings.length);
  assert.equal(
    Object.values(report.summary.bySeverity).reduce((a, b) => a + b, 0),
    findings.length,
  );
  assert.equal(
    Object.values(report.summary.byRule).reduce((a, b) => a + b, 0),
    findings.length,
  );
  assert.equal(report.summary.filesScanned, 12);
});

test('sarif output is valid SARIF 2.1.0', () => {
  const sarif = JSON.parse(formatSarif(findings));
  assert.equal(sarif.version, '2.1.0');
  assert.ok(typeof sarif.$schema === 'string' && sarif.$schema.includes('sarif-schema-2.1.0'));
  assert.equal(Array.isArray(sarif.runs), true);
  assert.equal(sarif.runs.length, 1);

  const [run] = sarif.runs;
  assert.equal(run.tool.driver.name, 'node-sandbox-audit');
  assert.equal(run.tool.driver.version, VERSION);
  assert.equal(run.tool.driver.rules.length, RULE_IDS.length);
  assert.equal(run.columnKind, 'utf16CodeUnits');
  assert.equal(run.results.length, findings.length);
});

test('sarif rules carry the metadata GitHub code scanning reads', () => {
  const [run] = buildSarifReport(findings).runs;
  for (const rule of run.tool.driver.rules) {
    assert.ok(RULE_IDS.includes(rule.id));
    assert.equal(rule.name, RULES[rule.id].name);
    assert.ok(['error', 'warning', 'note', 'none'].includes(rule.defaultConfiguration.level));
    assert.ok(rule.properties.tags.includes('security'));
    assert.ok(Number(rule.properties['security-severity']) > 0);
    assert.ok(typeof rule.shortDescription.text === 'string');
    assert.ok(typeof rule.help.markdown === 'string');
    assert.ok(typeof rule.helpUri === 'string');
  }
});

test('sarif results point back at a real region and the right rule index', () => {
  const [run] = buildSarifReport(findings).runs;
  run.results.forEach((result, index) => {
    const finding = findings[index];
    assert.equal(result.ruleId, finding.ruleId);
    assert.equal(run.tool.driver.rules[result.ruleIndex].id, finding.ruleId);
    assert.ok(result.message.text.includes(finding.message));
    assert.ok(result.message.text.includes('Fix:'));

    const region = result.locations[0].physicalLocation.region;
    assert.equal(region.startLine, finding.start.line);
    assert.equal(region.startColumn, finding.start.column);
    assert.equal(region.endLine, finding.end.line);
    assert.equal(region.endColumn, finding.end.column);
    assert.equal(region.snippet.text, finding.snippet);

    const uri = result.locations[0].physicalLocation.artifactLocation.uri;
    assert.ok(uri.startsWith('/') === false, 'paths stay relative for code scanning');
    assert.ok(/^[0-9a-f]{16}$/.test(result.partialFingerprints.nodeSandboxAudit_v1));
  });
});

test('sarif emits uriBaseId only when asked for', () => {
  const withBase = buildSarifReport(findings, { uriBase: 'SRCROOT' });
  const withoutBase = buildSarifReport(findings);
  assert.equal(
    withBase.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId,
    'SRCROOT',
  );
  assert.equal(
    'uriBaseId' in withoutBase.runs[0].results[0].locations[0].physicalLocation.artifactLocation,
    false,
  );
});

test('sarif for a clean scan is still a valid run with no results', () => {
  const sarif = buildSarifReport([]);
  assert.equal(sarif.version, '2.1.0');
  assert.deepEqual(sarif.runs[0].results, []);
  assert.equal(sarif.runs[0].tool.driver.rules.length, RULE_IDS.length);
});
