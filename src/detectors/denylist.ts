import type { FileContext, ModuleNameCollection } from '../context.js';

/**
 * A literal collection of strings is treated as a module denylist when its intent is deny
 * (from its binding name, or from the polarity of the membership tests against it) and it
 * actually names Node builtins.
 *
 * The evidence bar depends on how deny intent was established. A binding name that says "blocked"
 * is strong, so one builtin entry plus a module-flavoured name is enough. Intent inferred from the
 * polarity of a membership test is weaker — it is keyed by name, and plenty of lists are tested for
 * membership without being import policy — so it requires two builtin entries. `['target',
 * 'module']` tested with `.includes()` is a compiler-option list, not a denylist.
 */
export function isModuleDenylist(collection: ModuleNameCollection): boolean {
  if (collection.polarity !== 'deny') return false;
  if (collection.builtinEntries.length >= 2) return true;
  return collection.polaritySource === 'name' && collection.moduleFlavoured;
}

export function moduleDenylists(ctx: FileContext): ModuleNameCollection[] {
  return ctx.collections.filter(isModuleDenylist);
}

export function describeCollection(collection: ModuleNameCollection): string {
  return collection.nameHint === null
    ? `the ${collection.kind} of blocked module names`
    : `\`${collection.nameHint}\``;
}
