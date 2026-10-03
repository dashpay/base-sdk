/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Reads places and locals. This covers what a local is projected
 *              from, where it goes and what is called on it.
 */

import lib.ast
import lib.traits
import lib.types
import rust

/**
 * Gets the place `e` projects from.
 *
 * A write or a wipe through a field, an element or a borrow lands in the
 * storage of the local underneath, so that local is what answers for it.
 */
Expr placeRoot(Expr e) {
  result = e and e instanceof VariableAccess
  or
  result = placeRoot(e.(FieldExpr).getContainer())
  or
  result = placeRoot(e.(IndexExpr).getBase())
  or
  result = placeRoot(e.(RefExpr).getExpr())
  or
  result = placeRoot(e.(ParenExpr).getExpr())
}

/** Gets an access of the local bound by `p`. */
VariableAccess accessOf(Pat p) { result = any(Variable v | v.getPat() = p).getAnAccess() }

/**
 * Holds if `e` is what `f` returns, as the operand of a `return` or as the
 * body's tail.
 */
predicate returnsExpr(Callable f, Expr e) {
  e = f.(Function).getFunctionBody().getStmtList().getTailExpr()
  or
  exists(ReturnExpr r | r.getEnclosingCallable() = f and e = r.getExpr())
}

/**
 * Holds if `e` is what `f` returns, by `return`, as the tail, or as the tail
 * of a block, branch or arm that is itself returned. A `return` inside a
 * closure returns from the closure, not from `f`.
 */
predicate returnedValue(Callable f, Expr e) {
  returnsExpr(f, e)
  or
  exists(BlockExpr b | returnedValue(f, b) and e = b.getStmtList().getTailExpr())
  or
  exists(IfExpr i | returnedValue(f, i) and e = [i.getThen().(Expr), i.getElse()])
  or
  exists(MatchExpr m | returnedValue(f, m) and e = m.getMatchArmList().getAnArm().getExpr())
}

/**
 * Holds if the local bound by `p` is consumed in place, moved by value into a
 * call, a struct literal or the tail of a block, rather than left behind. A
 * `return` does not count as a move here.
 */
predicate movedOut(Pat p) {
  accessOf(p) =
    [
      any(Call c).getAPositionalArgument(), any(StructExprField f).getExpr(),
      any(BlockExpr b).getStmtList().getTailExpr(),
      // A consuming method, `raw.into_iter()`, takes the local by value.
      any(MethodCallExpr mc | mc.getIdentifier().getText().matches("into\\_%")).getReceiver()
    ]
}

/**
 * Gets a method call on the local bound by `p`, or on a place projected from
 * it.
 */
MethodCallExpr callOn(Pat p) { placeRoot(result.getReceiver()) = accessOf(p) }

/** Holds if `method` is called on the local bound by `p`. */
predicate callsOn(Pat p, string method) { callOn(p).getIdentifier().getText() = method }

/**
 * Gets a type built with `va` as a field, as in `Self(va)`, `Name(va)` or
 * `Name { field: va }`.
 *
 * The type is what inference gives the constructor call, so a type of the same
 * name elsewhere is not mistaken for it.
 */
TypeItem constructedWith(VariableAccess va) {
  exists(CallExpr c | va = c.getArgList().getAnArg() and result = inferredItem(c) |
    calledName(c) = "Self" and
    result = any(Impl i | c.getEnclosingCallable() = implItem(i)).getSelf()
    or
    calledName(c) = nameOf(result) and isWorkspaceFile(fileOf(result))
  )
  or
  exists(StructExpr se |
    va = se.getStructExprFieldList().getAField().getExpr() and result = inferredItem(se)
  )
}
