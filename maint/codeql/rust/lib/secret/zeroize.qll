/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Reads what the `zeroize` crate does to a type or a function.
 *              This covers types that erase themselves, and erasing by hand.
 */

import lib.ast
import lib.policy
import lib.traits
import rust

/**
 * Holds if `f` erases something, by a method call or a path call.
 *
 * The match is on the `zeroize` prefix. This covers the
 * `<Self as Zeroize>::zeroize(self)` that a manual `Drop` needs, and a
 * backend's own helper.
 */
predicate callsZeroize(Function f) {
  exists(MethodCallExpr mc |
    mc.getEnclosingCallable() = f and
    mc.getIdentifier().getText().matches("zeroize%")
  )
  or
  exists(PathExpr pe |
    pe.getEnclosingCallable() = f and
    pathName(pe.getPath()).matches("zeroize%")
  )
}

/**
 * Holds if `t` erases its own storage.
 *
 * A bare `Drop` impl proves nothing, so its body must erase something.
 */
predicate wipesSelf(TypeItem t) {
  isWorkspaceFile(fileOf(t)) and hasTrait(t, ["Zeroize", "ZeroizeOnDrop"])
  or
  exists(Function d | d = methodOf(t, "Drop", "drop") |
    isWorkspaceFile(fileOf(d)) and callsZeroize(d)
  )
}

/**
 * Holds if the dependency type `t` erases itself on drop.
 *
 * Enumerated because the extractor keeps dependency function bodies out of
 * the database.
 */
predicate externalWiper(TypeItem t) {
  not isWorkspaceFile(fileOf(t)) and
  (
    // `blst::{min_pk,min_sig}::SecretKey` are declared `#[zeroize(drop)]`.
    nameOf(t) = "SecretKey" and
    fileOf(t).getAbsolutePath().matches("%/blst-%/src/lib.rs")
  )
}

/** Holds if `t` erases its own storage, without delegating to a field. */
predicate wipesDirectly(TypeItem t) {
  wipesSelf(t)
  or
  externalWiper(t)
}

/** Holds if `p` spells `Zeroizing::new`. */
predicate zeroizingNew(Path p) { pathName(p) = "new" and pathQualifierName(p) = "Zeroizing" }

/** Holds if `f` stages secret material through a wiping wrapper. */
predicate wipesInBody(Function f) {
  callsZeroize(f)
  or
  exists(PathExpr pe | pe.getEnclosingCallable() = f and zeroizingNew(pe.getPath()))
}
