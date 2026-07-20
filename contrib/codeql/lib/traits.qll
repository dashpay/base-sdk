/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Helpers for inspecting trait impls and derive macros.
 */

import lib.files
import rust

/** Gets the path from an impl block's trait reference. */
private Path implTraitPath(Impl i) { result = i.getTraitTy().(PathTypeRepr).getPath() }

/**
 * Holds if `i` implements `traitName` qualified under `crate`
 * (i.e. the trait path is `<crate>::<traitName>`).
 */
private predicate implTraitHasCrate(Impl i, string traitName, string crate) {
  exists(Path p |
    p = implTraitPath(i) and
    p.getSegment().getIdentifier().getText() = traitName and
    p.getQualifier().getSegment().getIdentifier().getText() = crate
  )
}

/** Gets the trait name from an impl block's trait reference. */
string implTraitName(Impl i) { result = implTraitPath(i).getSegment().getIdentifier().getText() }

/** Gets the type name from an impl block's self type. */
string implSelfName(Impl i) {
  result = i.getSelfTy().(PathTypeRepr).getPath().getSegment().getIdentifier().getText()
}

/** Holds if `t` has a derived impl for `traitName`. */
predicate hasDerivedImpl(TypeItem t, string traitName) {
  exists(MacroItems expansion, Impl i |
    expansion = t.getADeriveMacroExpansion() and
    i = expansion.getItem(_) and
    implTraitName(i) = traitName
  )
}

/** Materialises manual impl metadata for join efficiency. */
pragma[nomagic]
private predicate manualImplInfo(Impl i, File f, string selfName, string traitName, AstNode scope) {
  f = fileOf(i) and
  selfName = implSelfName(i) and
  traitName = implTraitName(i) and
  not exists(MacroItems m | i = m.getItem(_)) and
  scope = i.(AstNode).getParentNode()
}

/** Holds if `t` has a manual impl for `traitName`. */
predicate hasManualImpl(TypeItem t, string traitName) {
  exists(Impl i |
    manualImplInfo(i, fileOf(t), t.getName().getText(), traitName, t.(AstNode).getParentNode())
  )
}

/** Materialises macro impl metadata for join efficiency. */
pragma[nomagic]
private predicate macroImplInfo(MacroItems m, Impl i, File f, string selfName, string traitName) {
  i = m.getItem(_) and
  f = fileOf(i) and
  selfName = implSelfName(i) and
  traitName = implTraitName(i)
}

/** Holds if `t` has a macro-generated (non-derive) impl for `traitName`. */
predicate hasMacroImpl(TypeItem t, string traitName) {
  exists(MacroItems m, Impl i |
    macroImplInfo(m, i, fileOf(t), t.getName().getText(), traitName) and
    not m = t.getADeriveMacroExpansion()
  )
}

/** Holds if `t` implements `traitName` via derive, manual impl, or macro. */
predicate implementsTrait(TypeItem t, string traitName) {
  hasDerivedImpl(t, traitName) or
  hasManualImpl(t, traitName) or
  hasMacroImpl(t, traitName)
}

/**
 * Holds if `t` has a derived impl for `traitName` under `crate`
 * (i.e. the trait path is `::<crate>::<traitName>`).
 */
predicate hasDerivedImplInCrate(TypeItem t, string traitName, string crate) {
  exists(MacroItems expansion, Impl i |
    expansion = t.getADeriveMacroExpansion() and
    i = expansion.getItem(_) and
    implTraitHasCrate(i, traitName, crate)
  )
}

/**
 * Holds if `t` has a manual impl for `traitName` under `crate`
 * (i.e. the trait path is `<crate>::<traitName>`).
 */
predicate hasManualImplInCrate(TypeItem t, string traitName, string crate) {
  exists(Impl i |
    fileOf(i) = fileOf(t) and
    implSelfName(i) = t.getName().getText() and
    not exists(MacroItems m | i = m.getItem(_)) and
    implTraitHasCrate(i, traitName, crate) and
    i.(AstNode).getParentNode() = t.(AstNode).getParentNode()
  )
}

/**
 * Holds if `t` has a macro-generated (non-derive) impl for `traitName`
 * under `crate` (e.g. from `impl_num!`).
 */
predicate hasMacroImplInCrate(TypeItem t, string traitName, string crate) {
  exists(MacroItems m, Impl i |
    i = m.getItem(_) and
    not m = t.getADeriveMacroExpansion() and
    fileOf(i) = fileOf(t) and
    implSelfName(i) = t.getName().getText() and
    implTraitHasCrate(i, traitName, crate)
  )
}

/**
 * Holds if `t` implements `traitName` under `crate` via derive,
 * manual impl, or non-derive macro expansion.
 */
predicate implementsTraitInCrate(TypeItem t, string traitName, string crate) {
  hasDerivedImplInCrate(t, traitName, crate) or
  hasManualImplInCrate(t, traitName, crate) or
  hasMacroImplInCrate(t, traitName, crate)
}

/**
 * Binds a hand-written `impl Trait for t` that is not from a
 * cfg_attr-gated derive (which escapes MacroItems wrapping but
 * always falls inside the type definition span).
 */
pragma[nomagic]
predicate manualTraitImpl(TypeItem t, string trait, Impl i, int line) {
  manualImplInfo(i, fileOf(t), t.getName().getText(), trait, t.(AstNode).getParentNode()) and
  line = startLine(i) and
  not (line >= startLine(t) and line <= endLine(t))
}

/** Binds a macro-generated (non-derive) `impl Trait for t`. */
pragma[nomagic]
predicate macroTraitImpl(TypeItem t, string trait, Impl i, int line) {
  exists(MacroItems m |
    macroImplInfo(m, i, fileOf(t), t.getName().getText(), trait) and
    not m = t.getADeriveMacroExpansion() and
    line = startLine(i)
  )
}

/** Binds an inherent impl (no trait) for `t`. */
pragma[nomagic]
predicate inherentImpl(TypeItem t, Impl i, int line) {
  not exists(MacroItems m | i = m.getItem(_)) and
  fileOf(i) = fileOf(t) and
  implSelfName(i) = t.getName().getText() and
  not exists(implTraitName(i)) and
  i.(AstNode).getParentNode() = t.(AstNode).getParentNode() and
  line = startLine(i)
}
