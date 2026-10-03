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
import lib.secret.subtle
import lib.secret.zeroize
import lib.traits
import rust

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
    (P::secretByName(t) or wipesSelf(t)) and
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
   * recursively.
   */
  predicate zeroizeSatisfied(TypeItem t) {
    wipesDirectly(t)
    or
    fieldsWipe(t)
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
}
