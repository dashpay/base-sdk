/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Follows secret material into storage that nothing erases. It
 *              starts from what is secret by type and from what the code wraps
 *              in `Zeroizing`.
 */

import lib.ast
import lib.filters
import lib.paths
import lib.places
import lib.secret
import lib.secret.subtle
import lib.secret.zeroize
import lib.traits
import lib.types
import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking

/**
 * Holds if the local `local` of `function` is ignored as a sink.
 *
 * The function is owned by `owner` in `unit`. The local was audited by hand to
 * stage its secret safely, and naming it keeps the rest of the function under
 * the rules. Rows live in `secret.model.yml`.
 */
extensible private predicate ignoreSinks(string unit, string owner, string function, string local);

/**
 * Holds if the type at `path` is not treated as secret.
 *
 * A workspace type is no flow source, as it carries public ids and tweaks as
 * often as secrets. A dependency type stops the flow, as it carries only
 * public material. Rows live in `secret.model.yml`.
 */
extensible private predicate ignoreTypes(string path);

/** A path an `ignoreTypes` row names. */
private class IgnoredType extends ModelPath {
  IgnoredType() { ignoreTypes(this) }
}

/**
 * Holds if a variable named `name` carries a secret, whatever its type.
 *
 * The flow starts from every read of it, parameters included. Rows live in
 * `secret.model.yml`.
 */
extensible private predicate secretVariables(string name);

/**
 * Holds if `tr` hands back owned bytes that nothing will erase.
 *
 * An `Option` or `Result` carries its payload to the caller as bare as a plain
 * return would, so the wrapper is looked through.
 */
predicate bareCarrier(TypeRepr tr) {
  byteContainer(tr, _)
  or
  typeHead(tr) = ["Option", "Result"] and bareCarrier(firstTypeArg(tr))
}

/** Secret flow sources, sinks, barriers and steps under the policy `P`. */
module SecretFlow<SecretPolicySig P> {
  private module S = Secret<P>;

  /** Holds if the unit holding `f` defines a secret type. */
  private predicate holdsSecrets(File f) {
    exists(TypeItem t | S::enforcedSecretType(t) and P::unitOf(fileOf(t)) = P::unitOf(f))
  }

  /** Holds if `f` is covered by the secret flow rules. */
  predicate flowScope(Function f) {
    P::enforcedFile(fileOf(f)) and
    holdsSecrets(fileOf(f)) and
    not isTestCode(f)
  }

  /** Holds if `v` is a local that an `ignoreSinks` row names. */
  private predicate auditedLocal(Variable v) {
    exists(Function f | f = enclosingFunction(v.getPat()) |
      ignoreSinks(P::unitOf(fileOf(f)), ownerName(f), nameOf(f), v.getText())
    )
  }

  /**
   * Holds if `e` fills or reads an audited local, at its `let` initializer, by
   * access or by a copy taken out of it.
   */
  private predicate auditedSink(Expr e) {
    exists(Variable v | auditedLocal(v) |
      e = any(LetStmt s | s.getPat() = v.getPat()).getInitializer()
      or
      placeRoot([e, e.(PrefixExpr).getExpr()]) = v.getAnAccess()
    )
  }

  /** Holds if `va` reads a variable that a `secretVariables` row names. */
  private predicate secretVariable(VariableAccess va) {
    secretVariables(va.getVariable().getText()) and flowScope(enclosingFunction(va))
  }

  /**
   * Holds if `e` reads secret storage.
   *
   * This is a field of a type that is secret by name, other than a scalar flag
   * riding along with the bytes. A type that only erases, like a scratch
   * buffer, stages public data too and is no source.
   */
  predicate secretRead(Expr e) {
    exists(FieldExpr fe, TypeRepr fr, TypeItem t |
      fe = e and
      t = fieldOwner(fe, fr) and
      S::secretType(t) and
      P::secretByName(t) and
      not t = itemOf(any(IgnoredType p)) and
      not scalarRepr(fr) and
      not isTestCode(fe)
    )
  }

  /**
   * Holds if `e` converts secret material into a non-secret workspace type or a
   * scalar, which the type system declares public.
   */
  predicate declassified(Expr e) {
    scalarTyped(e)
    or
    exists(TypeItem t | t = inferredItem(e) |
      isWorkspaceFile(fileOf(t)) and
      not S::secretType(t) and
      not wipesDirectly(t)
      or
      not isWorkspaceFile(fileOf(t)) and
      t = itemOf(any(IgnoredType p))
    )
  }

  /** Holds if `e` is what the exposed function `f` returns as bare bytes. */
  predicate bareReturnSink(Expr e, Function f) {
    flowScope(f) and
    exposedFunction(f) and
    bareCarrier(f.getRetType().getTypeRepr()) and
    returnsExpr(f, e)
  }

  /**
   * Holds if `e` fills the local `p` binds, at its `let` initializer or through
   * an access, and that local stays put and is never erased.
   */
  predicate bareLocalSink(Expr e, IdentPat p) {
    S::coveredLocal(p) and
    flowScope(enclosingFunction(p)) and
    e = [any(LetStmt s | s.getPat() = p).getInitializer(), accessOf(p).(Expr)] and
    S::keptLocal(p) and
    S::neverWipes(p)
  }

  /**
   * Holds if `e` copies a value out of a `Zeroizing` by value, as a byte array
   * into a call whose callee cannot answer for it, or as a `Copy` operand of
   * an operator.
   *
   * The copy is a temporary that nothing erases, where a borrow of the wrapper
   * would leave the one copy there is. A non-`Copy` secret type of the
   * workspace takes the array as its own storage and erases it.
   */
  predicate copiedOutOfWiper(PrefixExpr e) {
    e.getOperatorName() = "*" and
    nameOf(inferredItem(e.getExpr())) = "Zeroizing" and
    flowScope(enclosingFunction(e)) and
    (
      arrayTyped(e) and
      exists(Call c | e = c.getAPositionalArgument() |
        not exists(Function f, Impl i, TypeItem t |
          f = c.getStaticTarget() and
          f = implItem(i) and
          i.getSelf() = t and
          S::secretType(t) and
          not hasTrait(t, "Copy")
        )
      )
      or
      // `current + *scalar` copies the scalar onto the stack, where a borrow,
      // `&*scalar`, reads it in place.
      copyTyped(e) and
      not arrayTyped(e) and
      not scalarTyped(e) and
      exists(BinaryExpr be | e = [be.getLhs(), be.getRhs()])
    )
  }

  /**
   * Holds if `e` is byte storage compared with `==` or `!=`.
   *
   * That compiles to `memcmp`, which stops at the first mismatch.
   */
  predicate comparedInVariableTime(Expr e) {
    exists(BinaryExpr be |
      be.getOperatorName() = ["==", "!="] and
      e = [be.getLhs(), be.getRhs()] and
      (arrayTyped(e) or S::bytesExpr(e) or e instanceof IndexExpr) and
      flowScope(enclosingFunction(be)) and
      not callsCtEq(enclosingFunction(be))
    )
  }

  /** Tracks secret storage into places that do not erase it. */
  module SecretFlowConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node n) { secretRead(n.asExpr()) or secretVariable(n.asExpr()) }

    predicate isSink(DataFlow::Node n) {
      (
        bareReturnSink(n.asExpr(), _) or
        bareLocalSink(n.asExpr(), _) or
        copiedOutOfWiper(n.asExpr()) or
        comparedInVariableTime(n.asExpr())
      ) and
      not auditedSink(n.asExpr())
    }

    predicate isBarrier(DataFlow::Node n) {
      declassified(n.asExpr())
      or
      // Tests feed secrets through public entry points on purpose.
      isTestCode(n.asExpr())
    }

    predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
      b.asExpr().(RefExpr).getExpr() = a.asExpr()
      or
      // `?` hands on the value it unwraps, however the carrier was tainted.
      b.asExpr().(TryExpr).getExpr() = a.asExpr()
      or
      // A dereference copies what the borrow points at, `*tweak`.
      b.asExpr().(PrefixExpr).getOperatorName() = "*" and
      b.asExpr().(PrefixExpr).getExpr() = a.asExpr()
      or
      // A view of or copy taken from a secret value is the value.
      exists(MethodCallExpr mc |
        mc.getReceiver() = a.asExpr() and
        b.asExpr() = mc and
        mc.getIdentifier().getText() =
          [
            "as_bytes", "as_ref", "as_mut", "as_slice", "as_array", "to_bytes", "into_bytes",
            "to_vec", "clone", "expose_secret"
          ]
      )
      or
      // A field or an element of a secret value is secret.
      b.asExpr().(FieldExpr).getContainer() = a.asExpr()
      or
      b.asExpr().(IndexExpr).getBase() = a.asExpr()
      or
      // A dependency may write what it computes into a place it was lent;
      // every read of that local is treated as carrying it afterwards.
      opaqueStep(a.asExpr(), b.asExpr())
    }

    predicate allowImplicitRead(DataFlow::Node n, DataFlow::ContentSet c) {
      isSink(n) and exists(c)
    }
  }

  /** Flow from secret storage to places that do not erase it. */
  module Storage = TaintTracking::Global<SecretFlowConfig>;

  /**
   * Tracks what the code declares secret, by wrapping it in `Zeroizing`, into
   * places that do not erase it.
   *
   * A qualified call that inference cannot resolve is not followed to its
   * result. From a value this common it fans out through every impl of a trait,
   * into code that never touches it.
   */
  module DeclaredSecretFlowConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node n) { zeroizingTyped(n.asExpr()) }

    predicate isSink(DataFlow::Node n) { SecretFlowConfig::isSink(n) }

    predicate isBarrier(DataFlow::Node n) { SecretFlowConfig::isBarrier(n) }

    predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
      SecretFlowConfig::isAdditionalFlowStep(a, b) and
      not exists(CallExpr c |
        c.(Call).getAnArgument() = a.asExpr() and
        b.asExpr() = c and
        not exists(c.(Call).getStaticTarget()) and
        exists(pathQualifierName(calledPath(c)))
      )
      or
      exists(CallExpr c, Function f, int i |
        pathCallTarget(c, f) and
        a.asExpr() = c.getArgList().getArg(i) and
        b.asParameter() = f.getParamList().getParam(i)
      )
    }

    predicate allowImplicitRead(DataFlow::Node n, DataFlow::ContentSet c) {
      isSink(n) and exists(c)
    }
  }

  /** Flow from values declared secret to places that do not erase them. */
  module Declared = DataFlow::Global<DeclaredSecretFlowConfig>;

  /**
   * Holds if a value declared secret reaches `sink` from a source in the same
   * directory, the module tree that owns it. Farther on, the trait calls it
   * passes through carry it into code that never held it.
   */
  predicate declaredSecretReaches(DataFlow::Node sink) {
    exists(DataFlow::Node src |
      Declared::flow(src, sink) and
      fileOf(src.asExpr()).getParentContainer() = fileOf(sink.asExpr()).getParentContainer()
    )
  }

  /** Holds if secret material reaches the sink `e` by either flow. */
  predicate secretReaches(Expr e) {
    exists(DataFlow::Node sink | e = sink.asExpr() |
      Storage::flowTo(sink) or declaredSecretReaches(sink)
    )
  }

  /** Holds if secret material is returned by `e` as bare bytes. */
  predicate bareReturnEscape(Expr e) { secretReaches(e) and bareReturnSink(e, _) }

  /** Holds if secret material is held in the local `p` binds, never erased. */
  predicate unwipedLocalEscape(IdentPat p) {
    exists(Expr e | secretReaches(e) and bareLocalSink(e, p))
  }

  /** Holds if `e` copies secret material out of `Zeroizing` by value. */
  predicate copiedOutEscape(PrefixExpr e) { secretReaches(e) and copiedOutOfWiper(e) }

  /** Holds if `e` is secret material compared with an early-exit operator. */
  predicate variableTimeCompareEscape(Expr e) { secretReaches(e) and comparedInVariableTime(e) }
}
