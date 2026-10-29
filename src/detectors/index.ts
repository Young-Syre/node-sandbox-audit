import type { FileContext } from '../context.js';
import type { Finding, RuleId } from '../types.js';

import * as nsa001 from './nsa001-denylist-missing-realm-escape.js';
import * as nsa002 from './nsa002-denylist-instead-of-allowlist.js';
import * as nsa003 from './nsa003-empty-or-leaky-context.js';
import * as nsa004 from './nsa004-run-in-this-context.js';
import * as nsa005 from './nsa005-missing-timeout.js';
import * as nsa006 from './nsa006-vm2-usage.js';
import * as nsa007 from './nsa007-isolated-vm-reference-leak.js';
import * as nsa008 from './nsa008-prototype-bridge.js';

export interface Detector {
  ruleId: RuleId;
  detect: (ctx: FileContext) => Finding[];
}

export const DETECTORS: readonly Detector[] = [
  { ruleId: 'NSA001', detect: nsa001.detect },
  { ruleId: 'NSA002', detect: nsa002.detect },
  { ruleId: 'NSA003', detect: nsa003.detect },
  { ruleId: 'NSA004', detect: nsa004.detect },
  { ruleId: 'NSA005', detect: nsa005.detect },
  { ruleId: 'NSA006', detect: nsa006.detect },
  { ruleId: 'NSA007', detect: nsa007.detect },
  { ruleId: 'NSA008', detect: nsa008.detect },
];
