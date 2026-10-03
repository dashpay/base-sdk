/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Rules over secret types. They must erase themselves, redact
 *              their contents, compare in constant time and stay off growable
 *              buffers.
 */

import lib.ast
import lib.filters
import lib.places
import lib.secret.subtle
import lib.secret.zeroize
import lib.traits
import lib.types
import rust
import codeql.rust.controlflow.ControlFlowGraph

/**
 * What a codebase decides about its secrets.
 *
 * It names the types that are secret by name, and the files the rules cover.
 */
signature module SecretPolicySig {
  /** Holds if `t` is declared secret by its name. */
  predicate secretByName(TypeItem t);

  /** Holds if `f` is a file the secret rules cover. */
  predicate enforcedFile(File f);

  /** Gets the unit holding `f`, such as its crate. */
  string unitOf(File f);
}

/**
 * Holds if `tr` names a heap-growable container.
 *
 * A `Vec` or `String` can reallocate while being filled, stranding a copy at
 * the old allocation that drop-time wiping cannot reach.
 */
predicate growableType(TypeRepr tr) {
  typeHead(tr) = ["Vec", "String", "VecDeque", "BTreeMap", "BTreeSet", "BinaryHeap"]
}

/**
 * Holds if `f` hands back a bare byte container.
 *
 * A `Zeroizing<..>` return is the wanted shape and a reference borrows rather
 * than copies, so neither is reported.
 */
predicate returnsBareBytes(Function f, string retType) {
  exists(TypeRepr tr |
    tr = f.getRetType().getTypeRepr() and
    (
      tr instanceof ArrayTypeRepr and
      typeHead(tr.(ArrayTypeRepr).getElementTypeRepr()) = "u8" and
      retType = "[u8; N]"
      or
      typeHead(tr) = ["Vec", "String"] and retType = typeHead(tr)
    )
  )
}

/**
 * Holds if `f` decides something with a short-circuiting adapter, named `how`.
 *
 * Such adapters walk only as far as the first byte that settles the answer.
 */
predicate stopsEarly(Function f, string how) {
  exists(MethodCallExpr mc, string name |
    mc.getEnclosingCallable() = f and
    name = mc.getIdentifier().getText() and
    name = ["all", "any", "position", "find", "contains", "starts_with", "ends_with"] and
    how = name + "()"
  )
}

/**
 * Holds if leaks in `function` are ignored until fixed.
 *
 * The function is owned by `owner` in `unit`. Other items have an empty
 * `owner` and are named by `function`. Rows live in `secret.model.yml`.
 */
extensible predicate ignoreLeak(string unit, string owner, string function);

/**
 * Gets what owns `f`.
 *
 * Model rows name a function by owner and name. A method's owner is its impl's
 * self type. A free function has no impl, so its file's stem stands in.
 */
string ownerName(Function f) {
  result = implSelfName(any(Impl i | f = implItem(i)))
  or
  not f = implItem(_) and result = fileOf(f).getStem()
}

/** Gets the function `n` sits in, looking through any closures around it. */
Function enclosingFunction(AstNode n) {
  result = n.getEnclosingCallable()
  or
  result = enclosingFunction(n.getEnclosingCallable().(ClosureExpr))
}

/**
 * Holds if `f` comes from a derive.
 *
 * Its bindings borrow the fields they name, while inference gives them the
 * field's own type.
 */
predicate derivedFunction(Function f) {
  f = implItem(any(TypeItem t).getADeriveMacroExpansion().getItem(_).(Impl))
}

/**
 * Holds if the callable binding the local `p` binds returns it bare.
 *
 * Wrapping it in `Some`, `Ok`, `CtOption` or a value built to return hands
 * the caller the same storage, so the local is not left behind.
 */
predicate returnedLocal(Pat p) {
  exists(Callable f, VariableAccess va | f = p.getEnclosingCallable() and va = accessOf(p) |
    returnedValue(f, va)
    or
    returnedValue(f,
      any(CallExpr c |
        (calledName(c) = ["Some", "Ok"] or ctOptionNew(calledPath(c))) and
        va = c.getArgList().getAnArg()
      ))
    or
    returnedValue(f,
      any(CallExpr c | va = c.getArgList().getAnArg() and exists(constructedWith(va))))
    or
    returnedValue(f, any(StructExpr se | va = se.getStructExprFieldList().getAField().getExpr()))
  )
}

/** Gets the control flow node of `n`. */
private CfgNode cfgOf(AstNode n) { result.getAstNode() = n }

/** Holds if `wipe` erases the local `p` binds by hand. */
private predicate wipeOf(IdentPat p, MethodCallExpr wipe) {
  wipe.getIdentifier().getText() = "zeroize" and
  placeRoot(wipe.getReceiver()) = accessOf(p)
}

/**
 * Holds if `n` runs after the local `p` binds is declared and before any of
 * its wipes, on some path.
 *
 * A path is not followed past a wipe. In a loop body that wipes its local
 * before looping, the next iteration starts with nothing left to erase.
 */
private predicate unwipedAt(IdentPat p, CfgNode n) {
  wipeOf(p, _) and
  n = cfgOf(any(LetStmt decl | decl.getPat() = p)).getASuccessor()
  or
  exists(CfgNode prev | unwipedAt(p, prev) and not wipeOf(p, prev.getAstNode()) |
    n = prev.getASuccessor()
  )
}

/** Holds if a wipe of the local `p` binds is reachable from `n`. */
private predicate reachesWipe(IdentPat p, CfgNode n) {
  wipeOf(p, n.getAstNode())
  or
  reachesWipe(p, n.getASuccessor())
}

/**
 * Holds if `t` is a `?` the local `p` binds is live and unwiped at, on a path
 * that goes on to the `zeroize` that ends its life.
 *
 * The failing path leaves the function without reaching the erase. Paths are
 * read off the control flow graph, so a `?` in a closure, which leaves the
 * closure alone, is not counted. One inside the declaration binds nothing yet.
 */
predicate skipsWipe(IdentPat p, TryExpr t) {
  unwipedAt(p, cfgOf(t)) and
  reachesWipe(p, cfgOf(t)) and
  not t.getParentNode*() = any(LetStmt decl | decl.getPat() = p)
}

/** The secret handling rules over types under the policy `P`. */
module Secret<SecretPolicySig P> {
  /**
   * Holds if `t` is a secret-bearing type.
   *
   * This keeps macro-generated items, which `isSourceType` drops. A macro can
   * mint secret bags wholesale, and dropping them would leave those types
   * unchecked.
   */
  predicate secretType(TypeItem t) {
    (P::secretByName(t) or declaresErase(t)) and
    fileOf(t).fromSource() and
    not isTestCode(t)
  }

  /** Holds if `t` is a secret-bearing type in a file the policy covers. */
  predicate enforcedSecretType(TypeItem t) {
    secretType(t) and
    P::enforcedFile(fileOf(t))
  }

  /**
   * Holds if a field written as `tr` may hold secret material.
   */
  predicate fieldMayHoldSecret(TypeRepr tr) {
    P::secretByName(namedTypeItem(tr))
    or
    growableType(tr)
    or
    tr instanceof ArrayTypeRepr
  }

  /**
   * Holds if a field written as `tr` keeps secret material nothing erases.
   *
   * The check is recursive. A field that neither erases itself nor sits inside
   * `Zeroizing` is cleared only when everything it is built from is. A field
   * with nothing to descend into has nowhere to delegate, so it stays reported.
   */
  predicate fieldNotWiped(TypeRepr tr) {
    fieldMayHoldSecret(tr) and
    not typeHead(tr) = "Zeroizing" and
    not wipesDirectly(namedTypeItem(tr)) and
    (
      not exists(fieldTypeRepr(namedTypeItem(tr)))
      or
      fieldNotWiped(fieldTypeRepr(namedTypeItem(tr)))
    )
  }

  /**
   * Holds if every field of `t` is erased or holds no secret, at any depth.
   *
   * Each field is checked alone, as one wrapped field says nothing about its
   * siblings.
   */
  predicate fieldsWipe(TypeItem t) {
    exists(fieldTypeRepr(t)) and
    not fieldNotWiped(fieldTypeRepr(t))
  }

  /**
   * Holds if something erases the secret material in `t`.
   *
   * Either `t` erases itself, or every secret-bearing field it holds is erased,
   * recursively. A type that is secret only for declaring `Zeroize` leaves the
   * erase to whoever holds it.
   */
  predicate zeroizeSatisfied(TypeItem t) {
    wipesDirectly(t)
    or
    fieldsWipe(t)
    or
    declaresErase(t) and not P::secretByName(t)
  }

  /**
   * Holds if `e` reads byte storage rather than an opaque value.
   *
   * Fields are judged by their declared type, so a flag beside the bytes is not
   * mistaken for them. References and derefs are looked through.
   */
  predicate bytesExpr(Expr e) {
    e instanceof ArrayExpr
    or
    e.(MethodCallExpr).getIdentifier().getText() =
      ["as_bytes", "as_ref", "as_slice", "to_bytes", "into_bytes", "as_array", "expose_secret"]
    or
    fieldMayHoldSecret(e.(FieldExpr).getStructField().getTypeRepr())
    or
    fieldMayHoldSecret(e.(FieldExpr).getTupleField().getTypeRepr())
    or
    bytesExpr(e.(RefExpr).getExpr())
    or
    bytesExpr(e.(PrefixExpr).getExpr())
  }

  /**
   * Holds if `f` compares byte storage with `how`, which stops early.
   *
   * `==` on bytes compiles to `memcmp`, which stops at the first mismatch. The
   * operand check keeps the rule on byte storage, so a flag or a length beside
   * the secret is not reported. `variableTimeSecretTest` judges secrecy.
   */
  predicate comparesBytes(Function f, string how) {
    exists(BinaryExpr be |
      be.getEnclosingCallable() = f and
      be.getOperatorName() = ["==", "!="] and
      bytesExpr([be.getLhs(), be.getRhs()]) and
      how = be.getOperatorName()
    )
  }

  /** Holds if nothing erases the secret material in `t`. */
  predicate unwipedSecret(TypeItem t) {
    enforcedSecretType(t) and
    not zeroizeSatisfied(t)
  }

  /** Holds if `t` can be formatted without redacting its contents. */
  predicate unredactedSecret(TypeItem t, string cause) {
    enforcedSecretType(t) and
    (
      hasDerivedImpl(t, "Debug") and cause = "derives Debug"
      or
      hasDerivedImpl(t, "Display") and cause = "derives Display"
      or
      not implementsTrait(t, "Debug") and cause = "has no manual Debug"
    )
  }

  /**
   * Holds if `f` erases internally but hands the caller a bare `retType`.
   *
   * Erasing that copy is left to the caller.
   */
  predicate leakedWipedBytes(Function f, string retType) {
    P::enforcedFile(fileOf(f)) and
    not isTestCode(f) and
    wipesInBody(f) and
    returnsBareBytes(f, retType)
  }

  /** Holds if `t` can be compared in a time that depends on its contents. */
  predicate variableTimeSecretEq(TypeItem t) {
    enforcedSecretType(t) and
    implementsTrait(t, "PartialEq") and
    not constantTimeEq(t)
  }

  /**
   * Holds if a method of a secret type answers a yes/no question about its own
   * bytes in variable time, using `how`.
   *
   * `PartialEq` has its own rule, so `eq` is skipped. This covers predicates
   * beside it, such as an `is_null` that returns at the first non-zero byte and
   * so leaks the length of the leading run of zeroes.
   */
  predicate variableTimeSecretTest(Function f, string how) {
    exists(TypeItem t, Impl i |
      enforcedSecretType(t) and
      i.getSelf() = t and
      f = implItem(i) and
      not isTestCode(f) and
      not nameOf(f) = "eq" and
      typeHead(f.getRetType().getTypeRepr()) = "bool" and
      (
        stopsEarly(f, how)
        or
        comparesBytes(f, how)
      ) and
      not callsCtEq(f)
    )
  }

  /**
   * Holds if leaks reported at `l` are ignored.
   *
   * Either `l` is the item, or it sits in the function, that an `ignoreLeak`
   * row names.
   */
  predicate ignoreLeakAt(Locatable l) {
    exists(Function f | f = l or f = enclosingFunction(l) |
      ignoreLeak(P::unitOf(fileOf(f)), ownerName(f), nameOf(f))
    )
    or
    ignoreLeak(P::unitOf(fileOf(l.(TypeItem))), "", nameOf(l.(TypeItem)))
  }

  /** Holds if `f` is covered by the rules over locals. */
  private predicate localScope(Function f) {
    P::enforcedFile(fileOf(f)) and
    not isTestCode(f)
  }

  /**
   * Holds if `p` binds a local the rules cover, by `let`, `if let`, a `match`
   * arm or a closure parameter.
   *
   * A function parameter holds the caller's copy, which the caller's own
   * binding answers for.
   */
  private predicate coveredLocal(IdentPat p) {
    p = any(Variable v).getPat() and
    not p = any(Function f).getParamList().getAParam().getPat() and
    not derivedFunction(enclosingFunction(p)) and
    localScope(enclosingFunction(p))
  }

  /**
   * Holds if `va` builds a value of a workspace type that erases itself.
   *
   * It is built as `Self(va)`, `Name(va)` or `Self { field: va }`, which makes
   * that type its keeper.
   */
  private predicate handedToWiper(VariableAccess va) {
    zeroizeSatisfied(constructedWith(va))
    or
    exists(CallExpr c | va = c.getArgList().getAnArg() and zeroizingNew(calledPath(c)))
  }

  /**
   * Holds if the local bound by `p` stays behind where it was declared.
   *
   * It is neither erased, returned nor handed to a type that erases, and is
   * never moved out or is `Copy`, so a move leaves the original in place. A
   * `Copy` local handed to a type that erases passes a copy, so it too stays.
   */
  private predicate keptLocal(Pat p) {
    (copyTyped(p) or not movedOut(p)) and
    not wipedLocal(p) and
    not returnedLocal(p) and
    not (handedToWiper(accessOf(p)) and not copyTyped(p))
  }

  /**
   * Holds if the local bound by `p` owns storage that nothing erases.
   *
   * That is an array, or a dependency type not known to erase itself, `Vec`
   * included. `Zeroizing`, `Option` and `Result` answer for their contents. A
   * scalar has nothing worth erasing, and a borrow owns nothing.
   */
  private predicate neverWipes(Pat p) {
    not borrowTyped(p) and
    (
      arrayTyped(p)
      or
      exists(TypeItem t | t = inferredItem(p) |
        not isWorkspaceFile(fileOf(t)) and
        not wipesDirectly(t) and
        not nameOf(t) = ["Zeroizing", "Option", "Result"] and
        not scalarTyped(p)
      )
    )
  }

  /**
   * Holds if `p` binds a dependency's secret key and leaves it behind unerased.
   *
   * The key comes from the dependency's constructors and the workspace's RNG,
   * not from a field of a workspace type, so its type marks it as secret.
   */
  predicate keptDependencySecret(IdentPat p) {
    coveredLocal(p) and
    exists(TypeItem t | t = inferredItem(p) |
      not isWorkspaceFile(fileOf(t)) and
      P::secretByName(t) and
      not wipesDirectly(t)
    ) and
    keptLocal(p) and
    neverWipes(p)
  }

  /**
   * Holds if `p` binds a local erased by hand, which the path `t` skips.
   *
   * The local owns storage with no erasing `Drop`. The hand erase marks it as
   * secret, and `t` is a `?` that leaves the function before that erase.
   */
  predicate skippedWipe(IdentPat p, TryExpr t) {
    coveredLocal(p) and
    neverWipes(p) and
    skipsWipe(p, t)
  }
}
