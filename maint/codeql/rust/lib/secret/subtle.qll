/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Reads what the `subtle` crate does to a function or a type.
 *              This covers constant-time comparison.
 */

import lib.traits
import rust

/** Holds if `f` compares through `subtle`. */
predicate callsCtEq(Function f) {
  exists(MethodCallExpr mc |
    mc.getEnclosingCallable() = f and
    mc.getIdentifier().getText() = "ct_eq"
  )
  or
  exists(PathExpr pe |
    pe.getEnclosingCallable() = f and
    pathName(pe.getPath()) = "ct_eq"
  )
}

/**
 * Holds if `t` decides equality with `subtle`'s constant-time comparison.
 *
 * A derived `PartialEq` compares field by field and stops at the first
 * mismatch. How long it runs then reveals how much of the secret the caller
 * has guessed.
 */
predicate constantTimeEq(TypeItem t) { callsCtEq(methodOf(t, "PartialEq", "eq")) }
