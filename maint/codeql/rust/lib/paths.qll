/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Resolves the item paths that model rows name. A path is
 *              absolute, from the crate down, so one spelling names one item.
 */

import rust
private import codeql.rust.internal.PathResolution

/**
 * An item path a model row names, as `crate::module::Item`.
 *
 * The first segment is a crate and never a module, so `secp256k1::SecretKey`
 * is the dependency's type and a workspace type is spelled the same way, as
 * `dash_pkc::bls::scalar::Fr`. Rows join by extending this class.
 */
abstract class ModelPath extends string {
  bindingset[this]
  ModelPath() { any() }
}

/** Gets segment `i` of `p`. */
private string segment(ModelPath p, int i) { result = p.splitAt("::", i) }

/** Gets the number of segments of `p`. */
private int segments(ModelPath p) { result = count(int i | exists(segment(p, i))) }

/**
 * Gets what the first `i + 1` segments of `p` name.
 *
 * A crate is only ever the first segment, so a re-export of a crate, such as
 * `dash_pkc::__deps::secp256k1`, does not spell a second path to its items.
 */
private ItemNode prefixItem(ModelPath p, int i) {
  i = 0 and result.(CrateItemNode).getName() = segment(p, 0)
  or
  i > 0 and
  result = prefixItem(p, i - 1).getASuccessor(segment(p, i)) and
  not result instanceof CrateItemNode and
  not result instanceof ExternCrateItemNode
}

/** Gets the item `n` stands for, through any chain of type aliases. */
private ItemNode aliased(ItemNode n) {
  not n instanceof TypeAlias and result = n
  or
  result = aliased(resolvePath(n.(TypeAlias).getTypeRepr().(PathTypeRepr).getPath()))
}

/**
 * Gets the item `p` names, in every version of its crate. An alias names what
 * it stands for, and a crate or a module is no item.
 */
Item itemOf(ModelPath p) {
  result = aliased(prefixItem(p, segments(p) - 1)) and not result instanceof Module
}
