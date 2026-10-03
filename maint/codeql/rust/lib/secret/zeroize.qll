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
 * Holds if `f` erases something, as a method call or a qualified path call.
 *
 * Matched on the `zeroize` prefix: `<Self as Zeroize>::zeroize(self)` is the
 * spelling a manual `Drop` needs to reach the trait method, and a backend
 * wipes through its own helper.
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
 * Holds if `t` wipes its own storage.
 *
 * A bare `Drop` impl proves nothing on its own, so the body has to be seen
 * erasing something before the type counts as wiped.
 */
predicate wipesSelf(TypeItem t) {
  isWorkspaceFile(fileOf(t)) and
  (
    implementsTrait(t, ["Zeroize", "ZeroizeOnDrop"]) or
    hasDerive(t, ["Zeroize", "ZeroizeOnDrop"])
  )
  or
  exists(Impl i, Function d |
    i.getSelf() = t and
    implTraitName(i) = "Drop" and
    isWorkspaceFile(fileOf(i)) and
    d = implItem(i) and
    nameOf(d) = "drop" and
    callsZeroize(d)
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

/** Holds if `f` stages secret material through a wiping wrapper. */
predicate wipesInBody(Function f) {
  callsZeroize(f)
  or
  exists(PathExpr pe, Path p |
    pe.getEnclosingCallable() = f and
    p = pe.getPath() and
    pathName(p) = "new" and
    pathQualifierName(p) = "Zeroizing"
  )
}
