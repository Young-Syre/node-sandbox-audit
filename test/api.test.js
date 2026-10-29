import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  DEFAULT_EXCLUDED_DIRS,
  DEFAULT_EXTENSIONS,
  collectFiles,
  scanFiles,
  scanSource,
} from '../dist/index.js';
import { SAFE_DIR, VULNERABLE_DIR, fixturePath } from './helpers.js';

test('scanSource reports nothing for code that never touches a sandbox', () => {
  const code = `
    import { createServer } from 'node:http';
    const blocked = new Set(['/admin', '/internal']);
    createServer((req, res) => {
      if (blocked.has(req.url)) {
        res.statusCode = 403;
      }
      res.end('ok');
    }).listen(3000);
  `;
  assert.deepEqual(scanSource(code, 'server.js'), []);
});

test('scanSource throws a SyntaxError for unparseable input', () => {
  assert.throws(() => scanSource('const = ;', 'broken.js'), SyntaxError);
});

test('scanSource analyses CommonJS sources', () => {
  const findings = scanSource(
    "const vm = require('node:vm'); module.exports = () => vm.runInThisContext('process');",
    'script.cjs',
  );
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['NSA004', 'NSA005'],
  );
});

test('scanSource falls back to script mode for sources that are invalid as modules', () => {
  // `with` is a syntax error under the implicit strict mode of an ES module.
  const findings = scanSource(
    "const vm = require('vm'); with (opts) { vm.runInThisContext(code, { timeout: 10 }); }",
    'legacy.js',
  );
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['NSA004'],
  );
});

test('scanSource defaults the filename rather than throwing', () => {
  const [finding] = scanSource("require('vm2');");
  assert.equal(finding.file, '<input>');
});

test('the rules option restricts which detectors run', () => {
  const path = fixturePath('vulnerable', 'denylist-missing-vm.js');
  const findings = scanFiles([path], { rules: ['NSA005'] });
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['NSA005'],
  );
});

test('the ignoreRules option is applied after the rules option', () => {
  const path = fixturePath('vulnerable', 'denylist-missing-vm.js');
  const findings = scanFiles([path], { rules: ['NSA001', 'NSA005'], ignoreRules: ['NSA001'] });
  assert.deepEqual(
    findings.map((finding) => finding.ruleId),
    ['NSA005'],
  );
});

test('severityThreshold drops findings below the requested level', () => {
  const path = fixturePath('vulnerable', 'denylist-missing-vm.js');
  const all = scanFiles([path]);
  const critical = scanFiles([path], { severityThreshold: 'critical' });
  assert.ok(critical.length < all.length);
  assert.ok(critical.every((finding) => finding.severity === 'critical'));
});

test('scanFiles walks a directory and returns findings sorted by position', () => {
  const findings = scanFiles([VULNERABLE_DIR]);
  assert.ok(findings.length >= 20);
  for (let i = 1; i < findings.length; i += 1) {
    const previous = findings[i - 1];
    const current = findings[i];
    const ordered =
      previous.file < current.file ||
      (previous.file === current.file &&
        (previous.start.line < current.start.line ||
          (previous.start.line === current.start.line &&
            previous.start.column <= current.start.column)));
    assert.ok(ordered, `findings out of order at index ${i}`);
  }
});

test('scanFiles reports unreadable and unparseable files through onError', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nsa-errors-'));
  try {
    writeFileSync(join(dir, 'broken.js'), 'const = ;');
    const errors = [];
    const findings = scanFiles([dir, join(dir, 'missing.js')], {
      onError: (error) => errors.push(error),
    });
    assert.deepEqual(findings, []);
    assert.equal(errors.length, 2);
    assert.ok(errors.some((error) => error.message.startsWith('parse error:')));
    assert.ok(errors.some((error) => error.file.endsWith('missing.js')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('collectFiles skips excluded directories and non-matching extensions', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nsa-collect-'));
  try {
    mkdirSync(join(dir, 'node_modules'));
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'node_modules', 'dep.js'), '');
    writeFileSync(join(dir, 'src', 'kernel.mjs'), '');
    writeFileSync(join(dir, 'src', 'notes.txt'), '');
    writeFileSync(join(dir, 'README.md'), '');

    const found = collectFiles([dir], DEFAULT_EXTENSIONS, new Set(DEFAULT_EXCLUDED_DIRS));
    assert.deepEqual(found, [join(dir, 'src', 'kernel.mjs')]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('collectFiles always scans an explicitly named file whatever its extension', () => {
  const dir = mkdtempSync(join(tmpdir(), 'nsa-explicit-'));
  try {
    const path = join(dir, 'kernel.ts.bak');
    writeFileSync(path, '');
    assert.deepEqual(
      collectFiles([path], DEFAULT_EXTENSIONS, new Set(DEFAULT_EXCLUDED_DIRS)),
      [path],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('findings carry a code frame whose caret spans the offending node', () => {
  const [finding] = scanFiles([fixturePath('vulnerable', 'empty-context.js')]);
  const caretRow = finding.codeFrame.split('\n').find((row) => row.includes('^'));
  assert.equal((caretRow.match(/\^/g) ?? []).length, finding.end.column - finding.start.column);
  assert.ok(finding.codeFrame.includes(`${finding.start.line} |`));
});

test('the safe fixture directory is clean end to end', () => {
  assert.deepEqual(scanFiles([SAFE_DIR]), []);
});

test('a non-security list of names tested with includes() is not a denylist', () => {
  // Reduced from TypeScript's compiler-option table, which this heuristic used to misread.
  const code = `
    const computedOptions = {
      useDefineForClassFields: { dependencies: ['target', 'module'] },
    };
    export function dependsOn(option, name) {
      return computedOptions[option].dependencies.includes(name);
    }
  `;
  assert.deepEqual(scanSource(code, 'compiler-options.js'), []);
});

test('a membership test that only returns a boolean casts no vote', () => {
  // Reduced from fast-uri, which this heuristic used to misread as a denylist.
  const code = `
    const supportedSchemeNames = ['http', 'https', 'ws', 'wss', 'urn'];
    export function isValidSchemeName(name) {
      return supportedSchemeNames.indexOf(name) !== -1;
    }
  `;
  assert.deepEqual(scanSource(code, 'schemes.js'), []);
});

test('deny intent inferred from a rejecting guard needs more than one builtin name', () => {
  const weak = `
    const names = ['module', 'target'];
    export function load(name) {
      if (names.includes(name)) throw new Error('no');
      return import(name);
    }
  `;
  assert.deepEqual(scanSource(weak, 'weak.js'), []);

  const strong = `
    const names = ['module', 'child_process'];
    export function load(name) {
      if (names.includes(name)) throw new Error('no');
      return import(name);
    }
  `;
  assert.deepEqual(
    [...new Set(scanSource(strong, 'strong.js').map((finding) => finding.ruleId))],
    ['NSA001', 'NSA002'],
  );
});

test('indexOf-style guards are read with the right polarity', () => {
  const deny = `
    const names = ['fs', 'child_process'];
    export function load(name) {
      if (names.indexOf(name) !== -1) throw new Error('denied');
      return import(name);
    }
  `;
  assert.ok(scanSource(deny, 'deny.js').some((finding) => finding.ruleId === 'NSA002'));

  const allow = `
    const names = ['fs', 'path'];
    export function load(name) {
      if (names.indexOf(name) < 0) throw new Error('not permitted');
      return import(name);
    }
  `;
  assert.deepEqual(scanSource(allow, 'allow.js'), []);
});

test('a name stated as a denylist is enough with one builtin entry', () => {
  const findings = scanSource(
    "const blockedModules = ['child_process'];\nexport const deny = (m) => blockedModules.includes(m);",
    'named.js',
  );
  assert.ok(findings.some((finding) => finding.ruleId === 'NSA001'));
});

test('usage inference is skipped when a binding name is reused', () => {
  const code = `
    function allow(specifier) {
      const names = ['path', 'url'];
      if (!names.includes(specifier)) throw new Error('no');
    }
    function deny(specifier) {
      const names = ['fs', 'child_process'];
      if (names.includes(specifier)) throw new Error('no');
    }
  `;
  assert.deepEqual(scanSource(code, 'ambiguous.js'), []);
});
