/**
 * Minimal structural types over acorn's ESTree output.
 *
 * acorn-walk dispatches on `node.type`, so a visitor always knows the concrete shape it is
 * looking at. Each visitor narrows once, at the top, with `as`, and works with real property
 * types from there — rather than threading `unknown` through every access.
 */

export interface Position {
  line: number;
  column: number;
}

export interface NodeLoc {
  start: Position;
  end: Position;
}

export interface AstNode {
  type: string;
  start: number;
  end: number;
  loc?: NodeLoc | null;
  [key: string]: unknown;
}

export interface Identifier extends AstNode {
  type: 'Identifier';
  name: string;
}

export interface PrivateIdentifier extends AstNode {
  type: 'PrivateIdentifier';
  name: string;
}

export interface Literal extends AstNode {
  type: 'Literal';
  value: string | number | boolean | null | bigint | RegExp;
  raw?: string;
}

export interface TemplateLiteral extends AstNode {
  type: 'TemplateLiteral';
  quasis: Array<AstNode & { value: { cooked?: string | null; raw: string } }>;
  expressions: AstNode[];
}

export interface MemberExpression extends AstNode {
  type: 'MemberExpression';
  object: AstNode;
  property: AstNode;
  computed: boolean;
  optional?: boolean;
}

export interface CallExpression extends AstNode {
  type: 'CallExpression';
  callee: AstNode;
  arguments: AstNode[];
  optional?: boolean;
}

export interface NewExpression extends AstNode {
  type: 'NewExpression';
  callee: AstNode;
  arguments: AstNode[];
}

export interface ImportExpression extends AstNode {
  type: 'ImportExpression';
  source: AstNode;
}

export interface ArrayExpression extends AstNode {
  type: 'ArrayExpression';
  elements: Array<AstNode | null>;
}

export interface Property extends AstNode {
  type: 'Property';
  key: AstNode;
  value: AstNode;
  kind: 'init' | 'get' | 'set';
  computed: boolean;
  shorthand: boolean;
  method: boolean;
}

export interface SpreadElement extends AstNode {
  type: 'SpreadElement';
  argument: AstNode;
}

export interface ObjectExpression extends AstNode {
  type: 'ObjectExpression';
  properties: Array<Property | SpreadElement>;
}

export interface VariableDeclarator extends AstNode {
  type: 'VariableDeclarator';
  id: AstNode;
  init: AstNode | null;
}

export interface AssignmentExpression extends AstNode {
  type: 'AssignmentExpression';
  operator: string;
  left: AstNode;
  right: AstNode;
}

export interface UnaryExpression extends AstNode {
  type: 'UnaryExpression';
  operator: string;
  argument: AstNode;
  prefix: boolean;
}

export interface BinaryExpression extends AstNode {
  type: 'BinaryExpression';
  operator: string;
  left: AstNode;
  right: AstNode;
}

export interface AwaitExpression extends AstNode {
  type: 'AwaitExpression';
  argument: AstNode;
}

export interface IfStatement extends AstNode {
  type: 'IfStatement';
  test: AstNode;
  consequent: AstNode;
  alternate: AstNode | null;
}

export interface ImportSpecifierNode extends AstNode {
  type: 'ImportSpecifier' | 'ImportDefaultSpecifier' | 'ImportNamespaceSpecifier';
  local: Identifier;
  imported?: Identifier | Literal;
}

export interface ImportDeclaration extends AstNode {
  type: 'ImportDeclaration';
  specifiers: ImportSpecifierNode[];
  source: Literal;
}

export interface FunctionDeclaration extends AstNode {
  type: 'FunctionDeclaration';
  id: Identifier | null;
  params: AstNode[];
}

export interface ObjectPattern extends AstNode {
  type: 'ObjectPattern';
  properties: Array<Property | AstNode>;
}

export function isIdentifier(node: AstNode | null | undefined): node is Identifier {
  return node?.type === 'Identifier';
}

export function isLiteral(node: AstNode | null | undefined): node is Literal {
  return node?.type === 'Literal';
}

export function isMember(node: AstNode | null | undefined): node is MemberExpression {
  return node?.type === 'MemberExpression';
}

export function isFunctionish(node: AstNode | null | undefined): boolean {
  return (
    node?.type === 'FunctionExpression' ||
    node?.type === 'ArrowFunctionExpression' ||
    node?.type === 'FunctionDeclaration' ||
    node?.type === 'ClassExpression' ||
    node?.type === 'ClassDeclaration'
  );
}

/** String value of a node, for nodes that can be statically resolved to one. */
export function staticString(node: AstNode | null | undefined): string | null {
  if (!node) return null;
  if (isLiteral(node)) {
    return typeof node.value === 'string' ? node.value : null;
  }
  if (node.type === 'TemplateLiteral') {
    const tpl = node as TemplateLiteral;
    if (tpl.expressions.length !== 0 || tpl.quasis.length !== 1) return null;
    const only = tpl.quasis[0];
    return only ? (only.value.cooked ?? only.value.raw) : null;
  }
  return null;
}

/** Name of a property key — `a.b`, `a['b']`, `{ b: 1 }`, `{ 'b': 1 }`. */
export function propertyName(node: AstNode, computed: boolean): string | null {
  if (!computed && isIdentifier(node)) return node.name;
  if (!computed && node.type === 'PrivateIdentifier') return `#${(node as PrivateIdentifier).name}`;
  return staticString(node);
}

/** Dotted path of a member expression, or null if any link is dynamic. `a.b.c` -> ['a','b','c']. */
export function memberPath(node: AstNode): string[] | null {
  const parts: string[] = [];
  let current: AstNode = node;
  while (isMember(current)) {
    const name = propertyName(current.property, current.computed);
    if (name === null) return null;
    parts.unshift(name);
    current = current.object;
  }
  if (!isIdentifier(current)) return null;
  parts.unshift(current.name);
  return parts;
}

/** The root identifier of a member chain, e.g. `process` in `process.mainModule.require`. */
export function rootIdentifier(node: AstNode): Identifier | null {
  let current: AstNode = node;
  while (isMember(current)) current = current.object;
  return isIdentifier(current) ? current : null;
}

/** Positional argument, or null when absent. */
export function argAt(args: readonly AstNode[], index: number): AstNode | null {
  return args[index] ?? null;
}

/** The named property of an object literal, or null when absent or not a literal. */
export function objectProperty(node: AstNode | null, name: string): Property | null {
  if (node?.type !== 'ObjectExpression') return null;
  for (const prop of (node as ObjectExpression).properties) {
    if (prop.type !== 'Property') continue;
    const property = prop as Property;
    if (propertyName(property.key, property.computed) === name) return property;
  }
  return null;
}

export function objectHasSpread(node: AstNode | null): boolean {
  if (node?.type !== 'ObjectExpression') return false;
  return (node as ObjectExpression).properties.some((p) => p.type === 'SpreadElement');
}

export function isEmptyObjectLiteral(node: AstNode | null): boolean {
  return node?.type === 'ObjectExpression' && (node as ObjectExpression).properties.length === 0;
}

/** `Object.create(null)` with no property descriptors. */
export function isBareObjectCreateNull(node: AstNode | null): boolean {
  if (node?.type !== 'CallExpression') return false;
  const call = node as CallExpression;
  const path = memberPath(call.callee);
  if (!path || path.join('.') !== 'Object.create') return false;
  const first = argAt(call.arguments, 0);
  return (
    call.arguments.length <= 1 && isLiteral(first) && first.value === null
  );
}

export function isNullishLiteral(node: AstNode | null): boolean {
  if (!node) return false;
  if (isIdentifier(node) && node.name === 'undefined') return true;
  return isLiteral(node) && node.value === null;
}

/** Unwraps `await x` and parenthesised-looking wrappers acorn represents directly. */
export function unwrapAwait(node: AstNode): AstNode {
  let current = node;
  while (current.type === 'AwaitExpression') current = (current as AwaitExpression).argument;
  return current;
}
