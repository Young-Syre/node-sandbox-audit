# node-sandbox-audit

[![tests](https://github.com/Young-Syre/node-sandbox-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/node-sandbox-audit/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](package.json)
[![TypeScript: strict](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](tsconfig.json)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-informational.svg)](#github-code-scanning)

![license](https://img.shields.io/badge/license-MIT-blue.svg)
![node](https://img.shields.io/badge/node-%E2%89%A5%2020-5fa04e.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)
![output](https://img.shields.io/badge/output-SARIF%202.1.0-6f42c1.svg)
![runtime deps](https://img.shields.io/badge/runtime%20deps-2-lightgrey.svg)

Static detection of **incomplete module denylists** and **unsafe context configuration** in
JavaScript sandboxes built on `node:vm`, `vm2`, and `isolated-vm`.

It exists because the same mistake keeps shipping: a sandbox author enumerates the modules that
look dangerous — `process`, `child_process`, `fs` — blocks those, and treats the result as a
boundary. The list is always incomplete, because any module that can *evaluate code in another
realm* is transitively equal to every module on it. This tool finds those gaps and names the exact
escape that is reachable.

```console
$ node-sandbox-audit scan src --format text
src/kernel.mjs
  critical NSA001  denylist-missing-realm-escape  10:25
    Module denylist `BLOCKED_MODULES` blocks 3 specifier(s) but omits 8 realm-escape module(s):
    `vm`, `module`, `repl`, `inspector`, `async_hooks`, `perf_hooks`, `trace_events`, `v8`.
    Reaching any one of them is equivalent to loading every module the list denies.
      · Shortest chain: `const vm = await import("node:vm")` then `vm.runInThisContext("process")`
        returns the *host* process object, after which
        `process.mainModule.require("child_process")` loads anything the list denied.

    10 | const BLOCKED_MODULES = new Set(['process', 'child_process', 'worker_threads']);
       |                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

---

## `vm` is not a security boundary

Node's own documentation says so: the `node:vm` module is not a security mechanism and must not be
used to run untrusted code. That is worth taking literally, because the reason is structural rather
than a matter of missing hardening.

A `vm` context is a new **global object**, not a new **realm boundary**. Host and guest share one V8
isolate and one heap. So:

- Every value that crosses the boundary carries a prototype chain into the realm that made it.
  One host object is enough: `value.constructor.constructor('return process')()` compiles code in
  whichever realm owns that chain.
- `vm.runInThisContext` and `vm.compileFunction` (without `parsingContext`) evaluate in the
  *calling* realm by definition. They are not weakened sandboxes; they are not sandboxes.
- The module loader is not part of the context. Whatever hook you attach to resolve the guest's
  imports is host code, and the modules it can reach are the host's modules.

`isolated-vm` is a genuinely different proposition — separate isolate, separate heap — and that is
why it is the recommendation throughout this tool's remediation text. But its soundness is
conditional: a single `ivm.Reference` over a host function puts the bridge back (see
[NSA007](#nsa007)).

---

## The bug class

The shape these rules are built around is a concrete one, and it is worth walking through before the
rule table, because the rules only make sense against it. A JavaScript REPL evaluates untrusted code
with `vm.SourceTextModule` against `vm.createContext({})`, and guards imports with a three-entry
denylist: `process`, `child_process`, `worker_threads`. Every individual decision there looks
defensible.

The escape, as a sequence:

1. Guest source is evaluated as a `vm.SourceTextModule` whose context is `vm.createContext({})` —
   an empty global, which looks like the tightest possible sandbox.
2. The module's linker callback rejects a specifier if it appears in the denylist, and resolves it
   otherwise.
3. `node:vm` is not in the denylist. `import('node:vm')` is therefore allowed, and hands the guest
   the host's real `vm` module object.
4. `vm.runInThisContext(src)` compiles `src` in the realm of whoever calls it. That caller is the
   kernel. So the code runs in the **kernel's own context**, where `process` is in scope.
5. `vm.runInThisContext('process')` therefore returns the real `process` object — the very thing
   step 2 was supposed to deny.
6. From there the denylist is finished. `process.mainModule.require` (the kernel's entry point was
   CommonJS) reloads `child_process` and `fs`; `process.stdout.write` forges messages on the
   channel the host uses to talk to its client; `process.exit` and `process.kill` stop the host.

```js
// Guest code, running "inside" the sandbox.
const vm = await import('node:vm');                  // 'vm' was never denied
const host = vm.runInThisContext('process');          // evaluated in the kernel's realm
host.mainModule.require('child_process').execSync('id');
host.mainModule.require('fs').readFileSync('/etc/passwd', 'utf8');
host.stdout.write(forgedProtocolFrame);               // forge traffic on the host's channel
host.exit(0);                                         // or simply stop the host
```

**The generalisable lesson.** A denylist of *dangerous* modules is unsound, because any module that
can evaluate code in a different realm — `vm`, `module`, `repl`, `inspector`, `worker_threads` —
or that merely hands back an object built in another realm — `async_hooks`, `perf_hooks`,
`trace_events`, `v8` — is transitively equivalent to the modules you denied. Add the `node:`-prefixed
alias of each and the set you have to enumerate correctly is larger still, and it grows with every
Node release.

Allowlists are the only sound design: the permitted set is small, known, and fails closed. And no
import policy saves a `vm` context, because `vm` was never a boundary to begin with.

<details>
<summary>The realm-escape modules this tool checks for, and why each one is enough</summary>

| Module | Kind | Mechanism |
| --- | --- | --- |
| `vm` | evaluation | `vm.runInThisContext(src)` compiles `src` in the *calling* realm, where `process` and `require` are in scope. |
| `module` | evaluation | `module.createRequire(path)` returns a fully functional `require`, bypassing whatever loader hook the denylist is attached to. |
| `repl` | evaluation | `repl.start({ useGlobal: true })` attaches an evaluator that runs input against the host global object. |
| `inspector` | evaluation | `new inspector.Session().post('Runtime.evaluate', { expression })` evaluates in the inspected (host) context. |
| `worker_threads` | evaluation | `new Worker(src, { eval: true })` starts a thread with an unrestricted module loader; `SharedArrayBuffer` shares memory back. |
| `async_hooks` | host-object | `async_hooks.executionAsyncResource()` returns the host-realm resource object for the current execution. |
| `perf_hooks` | host-object | `performance.nodeTiming` and `PerformanceObserver` entries are host-realm objects. |
| `trace_events` | host-object | `trace_events.createTracing({ categories })` returns a host-realm `Tracing` object. |
| `v8` | host-object | `v8.setFlagsFromString` changes how later code is parsed; `v8.deserialize` builds host objects from attacker bytes. |

"Evaluation" modules give direct code execution in another realm. "Host-object" modules only hand
back an object — which is sufficient on its own, via
`obj.constructor.constructor('return process')()`.

</details>

---

## Rules

| ID | Severity | Rule | What it catches | Why it matters |
| --- | --- | --- | --- | --- |
| <a id="nsa001"></a>NSA001 | critical | `denylist-missing-realm-escape` | A module denylist that omits a realm-escape module, or that blocks only one of the two spellings of a module (`fs` but not `node:fs`). Reports exactly which escapes are reachable. | This is the flagship rule and the bug class above. One missing entry collapses the whole policy. |
| <a id="nsa002"></a>NSA002 | high | `denylist-instead-of-allowlist` | Import filtering expressed as a set of blocked modules rather than permitted ones. | A denylist is correct only while it is complete, and completeness cannot be established for the Node builtin surface. An allowlist fails closed. |
| <a id="nsa003"></a>NSA003 | high | `empty-or-leaky-context` | `vm.createContext({})` / `runInNewContext` with an empty context, or one seeded with `require`, `process`, `globalThis`, `Buffer`, or a host function. | An empty context is not an empty realm, and a seeded one is a direct bridge. |
| <a id="nsa004"></a>NSA004 | critical | `run-in-this-context` | `vm.runInThisContext`, `script.runInThisContext`, or `vm.compileFunction` without `parsingContext`. | These evaluate in the host realm by definition. This is the pivot that turns an incomplete denylist into a full escape. |
| <a id="nsa005"></a>NSA005 | medium | `missing-timeout` | A `vm` run or `SourceTextModule.evaluate` with no `timeout` option. | `while (true) {}` in guest code stops the thread. One request is a denial of service for every other request on it. |
| <a id="nsa006"></a>NSA006 | high | `vm2-usage` | Any import or require of `vm2`. | vm2 is discontinued after repeated sandbox-escape reports it could not fix structurally, and receives no further security fixes. |
| <a id="nsa007"></a>NSA007 | high | `isolated-vm-reference-leak` | `new ivm.Reference(...)`, or a transfer with `copy: false` / `reference: true`. | Isolate separation is what makes `isolated-vm` sound. A reference reintroduces the bridge it removed. |
| <a id="nsa008"></a>NSA008 | critical | `prototype-bridge` | A host object, host function, or prototype attached to the sandbox global — property assignment, `Object.assign`, `Object.setPrototypeOf`, or a `__proto__` key. | `this.constructor.constructor('return process')()` walks from any host object to the host `Function`. |

`node-sandbox-audit rules` prints this table from the tool itself; `rules --format json` emits it
as machine-readable metadata.

---

## Install

```bash
npm install --save-dev node-sandbox-audit
# or run it without installing
npx node-sandbox-audit scan src
```

Node 20 or newer. Two runtime dependencies, both pinned to exact versions: `acorn` and
`acorn-walk`.

## Usage

```
node-sandbox-audit scan <paths...> [options]
node-sandbox-audit rules [--format text|json]
```

| Option | Effect |
| --- | --- |
| `--format <text\|json\|sarif>` | Output format. Default `text`. |
| `--severity-threshold <level>` | Report findings at or above `low`, `medium`, `high`, `critical`. Default `low`. Also governs the `--exit-code` decision. |
| `--rule <id>` | Run only these rules. Repeatable and comma-separated. |
| `--ignore-rule <id>` | Skip these rules. Applied after `--rule`. |
| `--ext <list>` | Extensions picked up when walking directories. Default `.js,.mjs,.cjs`. An explicitly named file is always scanned. |
| `--exit-code` | Exit `1` when any finding is reported, for CI. |
| `--sarif-uri-base <id>` | Emit `uriBaseId` on SARIF locations, e.g. `SRCROOT`. |
| `--color` / `--no-color` | Force or disable ANSI colour. Default: auto, and `NO_COLOR` is honoured. |

Exit codes: `0` completed, `1` findings reported with `--exit-code`, `2` bad usage or no input.
`node_modules`, `.git`, `dist`, `build`, `coverage`, `.next` and `out` are skipped while walking.
Files that cannot be read or parsed produce a warning on stderr and are skipped, so stdout stays
machine-readable.

### Programmatic API

```ts
import { scanSource, scanFiles, RULES } from 'node-sandbox-audit';
import type { Finding } from 'node-sandbox-audit';

// A single source string. Throws SyntaxError if it cannot be parsed.
const findings: Finding[] = scanSource(source, 'kernel.mjs');

// Files and directories, with unparseable files reported rather than thrown.
const all = scanFiles(['src'], {
  severityThreshold: 'high',
  ignoreRules: ['NSA005'],
  onError: ({ file, message }) => console.warn(`skipped ${file}: ${message}`),
});

for (const finding of all) {
  console.log(`${finding.file}:${finding.start.line} ${finding.ruleId} ${finding.message}`);
  console.log(finding.codeFrame);
  console.log(RULES[finding.ruleId].rationale);
}
```

Every `Finding` carries `ruleId`, `ruleName`, `severity`, `message`, per-occurrence `details`,
`remediation`, `file`, 1-based `start`/`end` positions, a one-line `snippet`, and a rendered
`codeFrame`. `buildJsonReport`, `buildSarifReport`, `formatText`, `formatJson` and `formatSarif`
are exported too, so you can reuse the reporters without the CLI.

---

## GitHub code scanning

`--format sarif` emits valid SARIF 2.1.0, with `security-severity` properties so that code
scanning ranks the alerts rather than flattening them to SARIF's three levels.

```yaml
name: sandbox-audit

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Audit sandbox configuration
        run: >
          npx node-sandbox-audit scan src
          --format sarif
          --sarif-uri-base SRCROOT
          > sandbox-audit.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sandbox-audit.sarif

      - name: Fail on high-severity findings
        run: npx node-sandbox-audit scan src --severity-threshold high --exit-code
```

The upload step needs the scan to succeed, which is why gating is a separate step with
`--exit-code`. Drop that step if you want alerts without a blocking build.

---

## Known limitations

These are design boundaries, not a roadmap apology. Read them before trusting a clean run.

- **Static, single-file analysis. No cross-file dataflow.** A denylist declared in one module and
  consumed by a loader hook in another is not correlated. Each file is parsed and analysed on its
  own.
- **Allowlist/denylist classification is a heuristic.** Intent is inferred first from the binding
  name (`BLOCKED_MODULES`, `allowedModules`), and failing that from a membership test that *guards
  a rejection*: `if (list.has(x)) throw` reads as deny, `if (!list.has(x)) throw` as allow, and
  `indexOf`/comparison forms are read with the right polarity. A membership test that merely
  returns a boolean is a predicate, not a policy, and casts no vote — so a collection with an
  ambiguous name and no rejecting guard is skipped, and intent inferred from usage additionally
  requires two or more Node builtin names before NSA001 and NSA002 will fire. These are deliberate
  false negatives: a noisy NSA001 is an NSA001 that gets turned off.
- **Only literal collections are read.** A list built at runtime, read from JSON or config, or
  computed from another list is invisible.
- **Option bags are only inspected when written inline.** NSA004 and NSA005 skip a call whose
  options argument is a variable or contains a spread, rather than guessing. Pass the object at the
  call site if you want it checked.
- **Context objects are only inspected when written inline.** `const sandbox = { process };
  vm.createContext(sandbox)` is missed by NSA003; the same assignment written at the call site is
  caught.
- **JavaScript only** — `.js`, `.mjs`, `.cjs`. There is no TypeScript, JSX, Vue or Svelte parsing.
  Compile first and scan the emitted JS, or pass `--ext` with an explicit list of files that acorn
  can parse.
- **Module identity is the specifier as written.** No `tsconfig` paths, bundler aliases, or
  re-export chasing. A `vm` wrapper module of your own is not followed into.
- **NSA001 and NSA002 report the same node by design.** One describes the unsound design, the other
  the exploitable gap in it. Use `--ignore-rule NSA002` if you only want the gap.
- **The rules describe patterns, not intent.** A build tool or test harness that evaluates code it
  generated itself will legitimately trip NSA004 and NSA005 — the code really does run in the host
  realm, it simply is not untrusted. Triage by asking where the evaluated string comes from; use
  `--ignore-rule` or a narrower path for call sites whose input you control.
- **A clean run is not a safety proof.** `vm` is not a boundary even when no rule fires. If the
  code you are running is genuinely untrusted, the only sound answers are a separate process with
  an OS-level sandbox, or a separate isolate.

## Development

```bash
npm install
npm run build     # tsc, strict
npm test          # builds, then runs the node:test suites
```

The test suite pins every rule to a vulnerable fixture it must fire on *and* safe
counter-examples it must stay silent on, under `test/fixtures/`. The safe directory is asserted to
produce zero findings in total, which is what keeps the heuristics honest. Two of the regression
tests are reduced from real false positives found by scanning dependency trees — a compiler-option
table and a URI-scheme list, both of which an earlier version of the denylist heuristic misread.

### Measured noise

Fixtures only prove the rules do what their author expected. The useful question is what they do to
code nobody wrote for them, so here is a corpus you can reproduce:

```bash
mkdir /tmp/nsa-corpus && cd /tmp/nsa-corpus && npm init -y
npm i --no-audit --no-fund \
  eslint@9.15.0 webpack@5.96.1 rollup@4.27.4 express@4.21.1 \
  acorn@8.14.0 jest@29.7.0 handlebars@4.7.8 ejs@3.1.10
find node_modules -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) > files.txt
xargs -a files.txt -d '\n' -n 300 node-sandbox-audit scan --format text
```

**5,005 files. Seven findings, in four files, all of them webpack:**

| Rule | Count | Where | Is it real? |
| --- | --- | --- | --- |
| NSA004 `run-in-this-context` | 2 | `JavascriptModulesPlugin.js` | **Correct detection.** webpack really does call `vm.runInThisContext` on a string it assembles from generated module code. It is not a vulnerability *in webpack*, because the code being compiled is webpack's own build output rather than untrusted guest input. |
| NSA005 `missing-timeout` | 4 | `CssParser.js`, `JavascriptParser.js`, `JavascriptModulesPlugin.js` | **Correct detection.** No timeout is passed. Again not a vulnerability, for the same reason. |
| NSA003 `empty-or-leaky-context` | 1 | `magicComment.js` | **Partly the tool's fault, now fixed.** It reported `high` on `vm.createContext(undefined, …)` without reading the options object, which sets `codeGeneration: { strings: false }`. That makes `eval` and the `Function` constructor throw inside the context, which closes the exact prototype-chain escape NSA003's rationale is built on. It now reports `low`, says so, and names what the mitigation does *not* cover. |

So: zero misparses, and one rule whose severity was wrong in the presence of a mitigation it did not
look for. That last one is the honest shape of a static analyser's error bar — not a pattern that
failed to match, but a pattern that matched without reading enough context to grade itself.

The broader point this corpus makes is the one the tool cannot make for you: **every finding here is
a true detection and none is a bug.** These rules locate the `vm` surface and describe what it
would cost if the input were untrusted. Deciding whether it is untrusted is the reviewer's job, and
no severity field substitutes for it.

## References

- Node.js documentation, [`vm` — Executing JavaScript](https://nodejs.org/api/vm.html): states
  that the module is not a security mechanism and must not be used to run untrusted code, and
  documents that `vm.runInThisContext` compiles and runs code in the context of the current global
  object.
- Node.js documentation, [`vm.compileFunction`](https://nodejs.org/api/vm.html#vmcompilefunctioncode-params-options)
  and [`vm.createContext`](https://nodejs.org/api/vm.html#vmcreatecontextcontextobject-options):
  the `parsingContext` and context-object semantics NSA003 and NSA004 rely on.
- Node.js documentation, [`vm.SourceTextModule`](https://nodejs.org/api/vm.html#class-vmsourcetextmodule)
  and [`module.evaluate`](https://nodejs.org/api/vm.html#modulevaluateoptions): the ESM evaluation
  path, including its `timeout` option.
- [vm2](https://github.com/patriksimek/vm2): the repository states the project is discontinued and
  should not be used to run untrusted code, following repeated sandbox-escape reports.
- [isolated-vm](https://github.com/laverdet/isolated-vm): separate V8 isolate and heap, and the
  `Reference` / `ExternalCopy` transfer semantics behind NSA007.
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and GitHub's
  [SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning):
  the output contract, including `security-severity`.

## License

MIT © 2026 David Nichols
