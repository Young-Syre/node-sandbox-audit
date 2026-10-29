import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

import {
  argAt,
  isIdentifier,
  isLiteral,
  isMember,
  isFunctionish,
  memberPath,
  propertyName,
  rootIdentifier,
  staticString,
  unwrapAwait,
  type ArrayExpression,
  type AssignmentExpression,
  type AstNode,
  type BinaryExpression,
  type CallExpression,
  type Identifier,
  type ImportDeclaration,
  type IfStatement,
  type ImportExpression,
  type NewExpression,
  type ObjectExpression,
  type ObjectPattern,
  type Property,
  type UnaryExpression,
  type VariableDeclarator,
} from './ast.js';
import { NODE_BUILTINS, stripNodePrefix } from './builtins.js';

export type Polarity = 'deny' | 'allow' | 'unknown';

export interface ModuleRequest {
  /** Specifier exactly as written, e.g. 'node:vm'. */
  specifier: string;
  /** Specifier with any `node:` prefix removed. */
  module: string;
  kind: 'import' | 'require' | 'dynamic-import';
  node: AstNode;
}

export interface NamespaceBinding {
  localName: string;
  module: string;
  node: AstNode;
}

export interface MemberBinding {
  localName: string;
  module: string;
  member: string;
  node: AstNode;
}

export interface CollectionEntry {
  value: string;
  node: AstNode;
}

export interface ModuleNameCollection {
  node: AstNode;
  kind: 'set' | 'map' | 'array' | 'object';
  nameHint: string | null;
  entries: CollectionEntry[];
  builtinEntries: CollectionEntry[];
  polarity: Polarity;
  polaritySource: 'name' | 'usage' | 'none';
  /** The binding name mentions modules, imports, specifiers or packages. */
  moduleFlavoured: boolean;
}

/** Resolved `<module>.<member>` identity of a callee, e.g. `vm.runInThisContext`. */
export interface CalleeIdentity {
  module: string;
  member: string;
}

export interface ScriptMethodCall {
  method: string;
  /** True for a `vm.SourceTextModule` receiver rather than a `vm.Script` receiver. */
  onModule: boolean;
}

const DENY_WORDS = [
  'denylist',
  'denied',
  'deny',
  'blocklist',
  'blocked',
  'block',
  'blacklist',
  'banlist',
  'banned',
  'forbidden',
  'forbid',
  'disallowed',
  'disallow',
  'prohibited',
  'prohibit',
  'restricted',
  'rejected',
  'reject',
  'unsafe',
  'dangerous',
  'excluded',
];

const ALLOW_WORDS = [
  'allowlist',
  'allowed',
  'allow',
  'whitelist',
  'safelist',
  'permitted',
  'permit',
  'approved',
  'safe',
];

const MODULE_WORDS = ['module', 'import', 'require', 'specifier', 'package', 'builtin'];

function normaliseName(name: string): string {
  return name.toLowerCase().replace(/[^a-z]/g, '');
}

function matchesAny(normalised: string, words: readonly string[]): boolean {
  return words.some((word) => normalised.includes(word));
}

export class FileContext {
  readonly filename: string;
  readonly source: string;
  readonly lines: readonly string[];
  readonly ast: AstNode;

  readonly moduleRequests: ModuleRequest[] = [];
  readonly namespaceBindings = new Map<string, NamespaceBinding>();
  readonly memberBindings = new Map<string, MemberBinding>();

  /** Variables holding a `new vm.Script(...)`. */
  readonly scriptVars = new Set<string>();
  /** Variables holding a `new vm.SourceTextModule(...)` or `vm.SyntheticModule`. */
  readonly moduleVars = new Set<string>();
  /** Variables that are, or were contextified into, a `vm` sandbox global. */
  readonly sandboxVars = new Set<string>();
  /** Names bound to a host function or class in this file. */
  readonly hostFunctionNames = new Set<string>();

  readonly collections: ModuleNameCollection[] = [];

  private constructor(filename: string, source: string, ast: AstNode) {
    this.filename = filename;
    this.source = source;
    this.lines = source.split(/\r\n|\n|\r/);
    this.ast = ast;
  }

  static parse(source: string, filename: string): FileContext {
    const ast = parseProgram(source);
    const ctx = new FileContext(filename, source, ast);
    ctx.collectBindings();
    ctx.collectVmObjects();
    ctx.collectCollections();
    ctx.resolveCollectionPolarity();
    return ctx;
  }

  /** Walks every node with its ancestor chain. Ancestors are outermost-first, node last. */
  walk(visit: (node: AstNode, ancestors: readonly AstNode[]) => void): void {
    walk.fullAncestor(this.ast as unknown as acorn.Node, (node, _state, ancestors) => {
      visit(node as unknown as AstNode, ancestors as unknown as readonly AstNode[]);
    });
  }

  /** The module a local name refers to, if it is a namespace/default import binding. */
  moduleOf(localName: string): string | null {
    return this.namespaceBindings.get(localName)?.module ?? null;
  }

  /** Resolves a callee to `<module>.<member>` through import and destructuring bindings. */
  resolveCallee(callee: AstNode): CalleeIdentity | null {
    if (isIdentifier(callee)) {
      const bound = this.memberBindings.get(callee.name);
      return bound ? { module: bound.module, member: bound.member } : null;
    }
    if (isMember(callee)) {
      const member = propertyName(callee.property, callee.computed);
      if (member === null) return null;
      if (isIdentifier(callee.object)) {
        const module = this.moduleOf(callee.object.name);
        return module === null ? null : { module, member };
      }
      // `require('vm').runInThisContext(...)` and `(await import('node:vm')).runInThisContext(...)`
      const inlineModule = this.inlineRequireModule(callee.object);
      return inlineModule === null ? null : { module: inlineModule, member };
    }
    return null;
  }

  /** True when the callee resolves to exactly `<module>.<member>`. */
  calleeIs(callee: AstNode, module: string, member: string): boolean {
    const identity = this.resolveCallee(callee);
    return identity !== null && identity.module === module && identity.member === member;
  }

  /** The module requested by an inline `require(...)` / `import(...)` expression. */
  inlineRequireModule(node: AstNode): string | null {
    const expr = unwrapAwait(node);
    if (expr.type === 'ImportExpression') {
      const source = staticString((expr as ImportExpression).source);
      return source === null ? null : stripNodePrefix(source);
    }
    if (expr.type !== 'CallExpression') return null;
    const call = expr as CallExpression;
    if (isIdentifier(call.callee) && call.callee.name === 'require') {
      const source = staticString(argAt(call.arguments, 0));
      return source === null ? null : stripNodePrefix(source);
    }
    if (call.callee.type === 'Import') {
      const source = staticString(argAt(call.arguments, 0));
      return source === null ? null : stripNodePrefix(source);
    }
    return null;
  }

  /**
   * Resolves a `script.runInContext(...)` / `mod.evaluate(...)` style call, where the receiver is
   * a tracked `vm.Script` / `vm.SourceTextModule` variable or an inline construction of one.
   */
  resolveScriptMethod(call: CallExpression): ScriptMethodCall | null {
    if (!isMember(call.callee)) return null;
    const callee = call.callee;
    const method = propertyName(callee.property, callee.computed);
    if (method === null) return null;

    if (isIdentifier(callee.object)) {
      const name = callee.object.name;
      if (this.scriptVars.has(name)) return { method, onModule: false };
      if (this.moduleVars.has(name)) return { method, onModule: true };
      return null;
    }
    if (callee.object.type === 'NewExpression') {
      const constructed = this.resolveCallee((callee.object as NewExpression).callee);
      if (constructed?.module !== 'vm') return null;
      if (constructed.member === 'Script') return { method, onModule: false };
      if (constructed.member === 'SourceTextModule' || constructed.member === 'SyntheticModule') {
        return { method, onModule: true };
      }
    }
    return null;
  }

  /** True when the expression evaluates to a host-realm value reachable from this file. */
  isHostValue(node: AstNode): boolean {
    if (isFunctionish(node)) return true;
    const root = rootIdentifier(node);
    if (root === null) return false;
    if (this.namespaceBindings.has(root.name)) return true;
    if (this.memberBindings.has(root.name)) return true;
    if (this.hostFunctionNames.has(root.name)) return true;
    return false;
  }

  private addModuleRequest(specifier: string, kind: ModuleRequest['kind'], node: AstNode): void {
    this.moduleRequests.push({
      specifier,
      module: stripNodePrefix(specifier),
      kind,
      node,
    });
  }

  private bindNamespace(localName: string, module: string, node: AstNode): void {
    this.namespaceBindings.set(localName, { localName, module, node });
  }

  private bindMember(localName: string, module: string, member: string, node: AstNode): void {
    this.memberBindings.set(localName, { localName, module, member, node });
  }

  private collectBindings(): void {
    this.walk((node) => {
      switch (node.type) {
        case 'ImportDeclaration': {
          const decl = node as ImportDeclaration;
          const specifier = typeof decl.source.value === 'string' ? decl.source.value : null;
          if (specifier === null) return;
          this.addModuleRequest(specifier, 'import', decl);
          const module = stripNodePrefix(specifier);
          for (const spec of decl.specifiers) {
            if (spec.type === 'ImportSpecifier') {
              const imported = spec.imported;
              const name = imported
                ? isIdentifier(imported)
                  ? imported.name
                  : staticString(imported)
                : null;
              if (name !== null) this.bindMember(spec.local.name, module, name, spec);
            } else {
              this.bindNamespace(spec.local.name, module, spec);
            }
          }
          return;
        }
        case 'ImportExpression': {
          const source = staticString((node as ImportExpression).source);
          if (source !== null) this.addModuleRequest(source, 'dynamic-import', node);
          return;
        }
        case 'CallExpression': {
          const call = node as CallExpression;
          if (isIdentifier(call.callee) && call.callee.name === 'require') {
            const source = staticString(argAt(call.arguments, 0));
            if (source !== null) this.addModuleRequest(source, 'require', call);
          }
          return;
        }
        case 'FunctionDeclaration':
        case 'ClassDeclaration': {
          const id = (node as { id?: AstNode | null }).id;
          if (isIdentifier(id ?? undefined)) this.hostFunctionNames.add((id as Identifier).name);
          return;
        }
        case 'VariableDeclarator': {
          this.collectDeclaratorBindings(node as VariableDeclarator);
          return;
        }
        default:
          return;
      }
    });
  }

  private collectDeclaratorBindings(decl: VariableDeclarator): void {
    const init = decl.init;
    if (init === null) return;

    if (isIdentifier(decl.id) && isFunctionish(init)) {
      this.hostFunctionNames.add(decl.id.name);
    }

    const direct = this.inlineRequireModule(init);
    if (direct !== null) {
      this.bindPattern(decl.id, direct, null);
      return;
    }

    // `const run = require('vm').runInThisContext`
    const expr = unwrapAwait(init);
    if (isMember(expr)) {
      const module = this.inlineRequireModule(expr.object);
      const member = propertyName(expr.property, expr.computed);
      if (module !== null && member !== null && isIdentifier(decl.id)) {
        this.bindMember(decl.id.name, module, member, decl);
      }
      return;
    }

    // `const { createContext } = vm`
    if (isIdentifier(expr) && decl.id.type === 'ObjectPattern') {
      const module = this.moduleOf(expr.name);
      if (module !== null) this.bindPattern(decl.id, module, null);
    }
  }

  private bindPattern(pattern: AstNode, module: string, _member: string | null): void {
    if (isIdentifier(pattern)) {
      this.bindNamespace(pattern.name, module, pattern);
      return;
    }
    if (pattern.type !== 'ObjectPattern') return;
    for (const prop of (pattern as ObjectPattern).properties) {
      if (prop.type !== 'Property') continue;
      const property = prop as Property;
      const key = propertyName(property.key, property.computed);
      if (key === null || !isIdentifier(property.value)) continue;
      this.bindMember(property.value.name, module, key, property);
    }
  }

  private collectVmObjects(): void {
    this.walk((node) => {
      if (node.type === 'VariableDeclarator') {
        const decl = node as VariableDeclarator;
        if (decl.init === null || !isIdentifier(decl.id)) return;
        const init = unwrapAwait(decl.init);
        if (init.type === 'NewExpression') {
          const constructed = this.resolveCallee((init as NewExpression).callee);
          if (constructed?.module === 'vm') {
            if (constructed.member === 'Script') this.scriptVars.add(decl.id.name);
            if (constructed.member === 'SourceTextModule' || constructed.member === 'SyntheticModule') {
              this.moduleVars.add(decl.id.name);
            }
          }
          return;
        }
        if (init.type === 'CallExpression') {
          const call = init as CallExpression;
          if (this.calleeIs(call.callee, 'vm', 'createContext')) {
            this.sandboxVars.add(decl.id.name);
            this.markSandboxArgument(argAt(call.arguments, 0));
          }
        }
        return;
      }

      if (node.type !== 'CallExpression') return;
      const call = node as CallExpression;
      const identity = this.resolveCallee(call.callee);
      if (identity?.module === 'vm') {
        if (identity.member === 'createContext') {
          this.markSandboxArgument(argAt(call.arguments, 0));
        } else if (identity.member === 'runInNewContext' || identity.member === 'runInContext') {
          this.markSandboxArgument(argAt(call.arguments, 1));
        }
        return;
      }
      const scriptMethod = this.resolveScriptMethod(call);
      if (scriptMethod && !scriptMethod.onModule) {
        if (scriptMethod.method === 'runInNewContext' || scriptMethod.method === 'runInContext') {
          this.markSandboxArgument(argAt(call.arguments, 0));
        }
      }
    });
  }

  private markSandboxArgument(arg: AstNode | null): void {
    if (isIdentifier(arg ?? undefined)) this.sandboxVars.add((arg as Identifier).name);
  }

  private collectCollections(): void {
    this.walk((node, ancestors) => {
      const parent = ancestors[ancestors.length - 2] ?? null;

      if (node.type === 'NewExpression') {
        const construct = node as NewExpression;
        if (!isIdentifier(construct.callee)) return;
        const builder = construct.callee.name;
        if (builder !== 'Set' && builder !== 'Map') return;
        const arg = argAt(construct.arguments, 0);
        const entries =
          builder === 'Set' ? entriesFromArray(arg) : entriesFromMapPairs(arg);
        if (entries.length === 0) return;
        this.pushCollection(node, builder === 'Set' ? 'set' : 'map', entries, ancestors);
        return;
      }

      if (node.type === 'ArrayExpression') {
        // Skip the array literal handed to `new Set([...])` — recorded on the NewExpression.
        if (parent?.type === 'NewExpression' || parent?.type === 'SpreadElement') return;
        const entries = entriesFromArray(node);
        if (entries.length === 0) return;
        this.pushCollection(node, 'array', entries, ancestors);
        return;
      }

      if (node.type === 'ObjectExpression') {
        const entries = entriesFromObjectKeys(node as ObjectExpression);
        if (entries.length === 0) return;
        this.pushCollection(node, 'object', entries, ancestors);
      }
    });
  }

  private pushCollection(
    node: AstNode,
    kind: ModuleNameCollection['kind'],
    entries: CollectionEntry[],
    ancestors: readonly AstNode[],
  ): void {
    const builtinEntries = entries.filter((entry) => NODE_BUILTINS.has(stripNodePrefix(entry.value)));
    if (builtinEntries.length === 0) return;

    const nameHint = nameHintFrom(ancestors);
    const normalised = nameHint === null ? '' : normaliseName(nameHint);
    let polarity: Polarity = 'unknown';
    let polaritySource: ModuleNameCollection['polaritySource'] = 'none';
    if (matchesAny(normalised, DENY_WORDS)) {
      polarity = 'deny';
      polaritySource = 'name';
    } else if (matchesAny(normalised, ALLOW_WORDS)) {
      polarity = 'allow';
      polaritySource = 'name';
    }

    this.collections.push({
      node,
      kind,
      nameHint,
      entries,
      builtinEntries,
      polarity,
      polaritySource,
      moduleFlavoured: matchesAny(normalised, MODULE_WORDS),
    });
  }

  /**
   * For collections whose binding name says nothing, infer intent from membership tests that
   * actually reject: `if (list.has(x)) throw` is a denylist, `if (!list.has(x)) throw` is an
   * allowlist. A membership test that merely returns a boolean is a predicate, not a policy, and
   * casts no vote — `return schemes.indexOf(name) !== -1` is a validity check, not import
   * filtering.
   */
  private resolveCollectionPolarity(): void {
    const occurrences = new Map<string, number>();
    for (const collection of this.collections) {
      if (collection.nameHint === null) continue;
      occurrences.set(collection.nameHint, (occurrences.get(collection.nameHint) ?? 0) + 1);
    }

    const pending = new Map<string, ModuleNameCollection>();
    for (const collection of this.collections) {
      if (collection.polarity !== 'unknown' || collection.nameHint === null) continue;
      // A name bound to more than one collection cannot be attributed from usage alone.
      if (occurrences.get(collection.nameHint) !== 1) continue;
      pending.set(collection.nameHint, collection);
    }
    if (pending.size === 0) return;

    const votes = new Map<string, { deny: number; allow: number }>();
    const vote = (name: string, kind: 'deny' | 'allow'): void => {
      const tally = votes.get(name) ?? { deny: 0, allow: 0 };
      tally[kind] += 1;
      votes.set(name, tally);
    };

    this.walk((node, ancestors) => {
      const name = membershipTestTarget(node);
      if (name === null || !pending.has(name)) return;
      const inferred = guardVote(node, ancestors);
      if (inferred !== null) vote(name, inferred);
    });

    for (const [name, collection] of pending) {
      const tally = votes.get(name);
      if (!tally || tally.deny === tally.allow) continue;
      collection.polarity = tally.deny > tally.allow ? 'deny' : 'allow';
      collection.polaritySource = 'usage';
    }
  }
}

function parseProgram(source: string): AstNode {
  const options: acorn.Options = {
    ecmaVersion: 'latest',
    locations: true,
    allowHashBang: true,
    allowAwaitOutsideFunction: true,
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
  };
  try {
    return acorn.parse(source, { ...options, sourceType: 'module' }) as unknown as AstNode;
  } catch (moduleError) {
    try {
      return acorn.parse(source, { ...options, sourceType: 'script' }) as unknown as AstNode;
    } catch {
      throw moduleError;
    }
  }
}

function entriesFromArray(node: AstNode | null): CollectionEntry[] {
  if (node?.type !== 'ArrayExpression') return [];
  const entries: CollectionEntry[] = [];
  for (const element of (node as ArrayExpression).elements) {
    if (element === null) continue;
    const value = staticString(element);
    if (value !== null) entries.push({ value, node: element });
  }
  return entries;
}

function entriesFromMapPairs(node: AstNode | null): CollectionEntry[] {
  if (node?.type !== 'ArrayExpression') return [];
  const entries: CollectionEntry[] = [];
  for (const element of (node as ArrayExpression).elements) {
    if (element?.type !== 'ArrayExpression') continue;
    const key = argAt((element as ArrayExpression).elements.filter(nonNull), 0);
    const value = staticString(key);
    if (value !== null && key !== null) entries.push({ value, node: key });
  }
  return entries;
}

function nonNull(node: AstNode | null): node is AstNode {
  return node !== null;
}

function entriesFromObjectKeys(node: ObjectExpression): CollectionEntry[] {
  const entries: CollectionEntry[] = [];
  for (const prop of node.properties) {
    if (prop.type !== 'Property') return [];
    const property = prop as Property;
    if (property.kind !== 'init' || property.method) return [];
    const key = propertyName(property.key, property.computed);
    if (key === null) return [];
    // Only treat an object as a name set when every value is a plain flag.
    if (!isLiteral(property.value)) return [];
    entries.push({ value: key, node: property.key });
  }
  return entries;
}

/** Nearest enclosing binding name for a literal collection. */
function nameHintFrom(ancestors: readonly AstNode[]): string | null {
  for (let i = ancestors.length - 2; i >= 0; i -= 1) {
    const ancestor = ancestors[i];
    if (!ancestor) continue;
    if (ancestor.type === 'VariableDeclarator') {
      const id = (ancestor as VariableDeclarator).id;
      if (isIdentifier(id)) return id.name;
      return null;
    }
    if (ancestor.type === 'AssignmentExpression') {
      const left = (ancestor as AssignmentExpression).left;
      if (isIdentifier(left)) return left.name;
      if (isMember(left)) {
        const path = memberPath(left);
        return path === null ? null : (path[path.length - 1] ?? null);
      }
      return null;
    }
    if (ancestor.type === 'Property' || ancestor.type === 'PropertyDefinition') {
      const key = (ancestor as { key?: AstNode; computed?: boolean }).key;
      if (!key) return null;
      return propertyName(key, Boolean((ancestor as { computed?: boolean }).computed));
    }
    if (ancestor.type === 'NewExpression' || ancestor.type === 'ArrayExpression') continue;
    if (
      ancestor.type === 'CallExpression' ||
      ancestor.type === 'ReturnStatement' ||
      isFunctionish(ancestor)
    ) {
      return null;
    }
  }
  return null;
}

/** Name of the collection a membership test is performed against, if any. */
function membershipTestTarget(node: AstNode): string | null {
  if (node.type === 'CallExpression') {
    const call = node as CallExpression;
    if (!isMember(call.callee)) return null;
    const method = propertyName(call.callee.property, call.callee.computed);
    if (method === null) return null;
    if (!['has', 'includes', 'indexOf', 'hasOwnProperty', 'find', 'some'].includes(method)) {
      return null;
    }
    const receiver = call.callee.object;
    return isIdentifier(receiver) ? receiver.name : null;
  }
  if (node.type === 'BinaryExpression') {
    const binary = node as BinaryExpression;
    if (binary.operator !== 'in') return null;
    return isIdentifier(binary.right) ? binary.right.name : null;
  }
  if (isMember(node) && node.computed) {
    return isIdentifier(node.object) ? node.object.name : null;
  }
  return null;
}

/** A statically known primitive, including a negated numeric literal such as `-1`. */
function staticPrimitive(node: AstNode): { value: unknown } | null {
  if (isLiteral(node)) return { value: node.value };
  if (node.type === 'UnaryExpression') {
    const unary = node as UnaryExpression;
    if (unary.operator === '-' && isLiteral(unary.argument)) {
      const inner = unary.argument.value;
      if (typeof inner === 'number') return { value: -inner };
    }
  }
  return null;
}

/**
 * Whether a comparison preserves or inverts the sense of the membership test it wraps:
 * `indexOf(x) !== -1` still means "present", `indexOf(x) < 0` means "absent".
 */
function comparisonPolarity(binary: BinaryExpression, child: AstNode): 'same' | 'negated' | null {
  const other = binary.left === child ? binary.right : binary.left;
  const primitive = staticPrimitive(other);
  if (primitive === null) return null;
  const { value } = primitive;

  switch (binary.operator) {
    case '===':
    case '==':
      if (value === true) return 'same';
      if (value === false || value === -1) return 'negated';
      return null;
    case '!==':
    case '!=':
      if (value === true) return 'negated';
      if (value === false || value === -1) return 'same';
      return null;
    case '<':
      return value === 0 ? 'negated' : null;
    case '>':
      return value === -1 ? 'same' : null;
    case '>=':
      return value === 0 ? 'same' : null;
    default:
      return null;
  }
}

function isAstNode(value: unknown): value is AstNode {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

const SKIPPED_KEYS = new Set(['type', 'start', 'end', 'loc', 'range']);
const MAX_SUBTREE_DEPTH = 16;

function containsNodeType(node: AstNode, type: string, depth = 0): boolean {
  if (node.type === type) return true;
  if (depth >= MAX_SUBTREE_DEPTH) return false;
  for (const key of Object.keys(node)) {
    if (SKIPPED_KEYS.has(key)) continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item) && containsNodeType(item, type, depth + 1)) return true;
      }
    } else if (isAstNode(value) && containsNodeType(value, type, depth + 1)) {
      return true;
    }
  }
  return false;
}

/**
 * Reads a membership test as import policy, but only when it guards a rejection. Returns the
 * intent the collection must have for the guard to make sense, or null when the test is not a
 * rejecting guard at all.
 */
function guardVote(node: AstNode, ancestors: readonly AstNode[]): 'deny' | 'allow' | null {
  let child = node;
  let negated = false;

  for (let i = ancestors.length - 2; i >= 0; i -= 1) {
    const parent = ancestors[i];
    if (!parent) return null;

    switch (parent.type) {
      case 'UnaryExpression': {
        if ((parent as UnaryExpression).operator !== '!') return null;
        negated = !negated;
        break;
      }
      case 'BinaryExpression': {
        const polarity = comparisonPolarity(parent as BinaryExpression, child);
        if (polarity === null) return null;
        if (polarity === 'negated') negated = !negated;
        break;
      }
      case 'LogicalExpression':
      case 'ChainExpression':
        break;
      case 'IfStatement': {
        const ifStatement = parent as IfStatement;
        if (ifStatement.test !== child) return null;
        if (!containsNodeType(ifStatement.consequent, 'ThrowStatement')) return null;
        return negated ? 'allow' : 'deny';
      }
      default:
        return null;
    }
    child = parent;
  }

  return null;
}
