import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanSource } from '../dist/index.js';

export const TEST_DIR = dirname(fileURLToPath(import.meta.url));
export const PROJECT_ROOT = join(TEST_DIR, '..');
export const CLI = join(PROJECT_ROOT, 'dist', 'cli.js');
export const VULNERABLE_DIR = join(TEST_DIR, 'fixtures', 'vulnerable');
export const SAFE_DIR = join(TEST_DIR, 'fixtures', 'safe');

export function fixturePath(kind, name) {
  return join(TEST_DIR, 'fixtures', kind, name);
}

export function scanFixture(kind, name) {
  const path = fixturePath(kind, name);
  return scanSource(readFileSync(path, 'utf8'), path);
}

export function findingsFor(kind, name, ruleId) {
  return scanFixture(kind, name).filter((finding) => finding.ruleId === ruleId);
}

export function ruleIdsFor(kind, name) {
  return scanFixture(kind, name).map((finding) => finding.ruleId);
}
