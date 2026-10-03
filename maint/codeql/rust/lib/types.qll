/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Reads what a type spells and what its values may hold, through
 *              the type layer.
 */

import lib.ast
import lib.paths
import lib.policy
import rust
private import codeql.rust.internal.typeinference.Type as T
private import codeql.rust.internal.typeinference.TypeInference as TI

/** Gets the name of an integer primitive, `bool` or `char`. */
string scalarName() {
  result =
    [
      "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
      "bool", "char"
    ]
}

/**
 * Holds if `tr` spells a primitive scalar, with a valid all-zero bit pattern.
 */
predicate scalarRepr(TypeRepr tr) {
  typeHead(tr) = scalarName() and
  not exists(tr.(PathTypeRepr).getPath().getSegment().getGenericArgList())
}

/** Gets the workspace struct `tr` names. */
private Struct workspaceStruct(TypeRepr tr) {
  result = namedTypeItem(tr) and isWorkspaceFile(fileOf(result))
}

/**
 * Holds if the type `tr` may hold a value for which all zeroes is invalid.
 *
 * Only scalars, arrays of scalars and workspace structs of such fields are
 * spared. An enum tag, a reference, a `Vec` or a `Box` may not survive being
 * zeroed.
 */
predicate zeroInvalidRepr(TypeRepr tr) {
  not scalarRepr(tr) and
  not tr instanceof ArrayTypeRepr and
  not exists(workspaceStruct(tr))
  or
  zeroInvalidRepr([tr.(ArrayTypeRepr).getElementTypeRepr(), fieldTypeRepr(workspaceStruct(tr))])
}

/**
 * Holds if `s` is a workspace struct of plain data, valid as all zeroes at any
 * depth.
 */
predicate plainDataStruct(Struct s) {
  isWorkspaceFile(fileOf(s)) and not zeroInvalidRepr(fieldTypeRepr(s))
}

/**
 * Holds if `tr` spells an owned byte container of shape `kind`.
 *
 * Each owns its bytes outright, so a copy handed out in one of them is erased
 * by nobody but its new holder.
 */
predicate byteContainer(TypeRepr tr, string kind) {
  typeHead(tr.(ArrayTypeRepr).getElementTypeRepr()) = "u8" and kind = "[u8; N]"
  or
  typeHead(tr) = "String" and kind = typeHead(tr)
  or
  // Elements other than bytes erase themselves through their own types.
  typeHead(tr) = "Vec" and
  typeHead(firstTypeArg(tr)) = "u8" and
  kind = typeHead(tr)
}

/** Gets the type item `n` resolves to, if it resolves to a nominal type. */
TypeItem inferredItem(AstNode n) { result = TI::inferType(n).(T::DataType).getTypeItem() }

/**
 * Holds if `n` resolves to a scalar or `()`, which have no storage worth
 * wiping.
 */
predicate scalarTyped(AstNode n) {
  nameOf(inferredItem(n)) = scalarName() or TI::inferType(n) instanceof T::UnitType
}

/** Holds if `n` resolves to an array, which copies on assignment. */
predicate arrayTyped(AstNode n) { TI::inferType(n) instanceof T::ArrayType }

/**
 * Holds if `n` resolves to a reference, pointer or slice, which owns no
 * storage.
 */
predicate borrowTyped(AstNode n) {
  exists(T::Type t | t = TI::inferType(n) |
    t instanceof T::RefType or t instanceof T::PtrType or t instanceof T::SliceType
  )
}

/**
 * Holds if the dependency type at `path` is `Copy`.
 *
 * The extractor leaves dependency derives unexpanded. Rows live in
 * `secret.model.yml`.
 */
extensible predicate allowCopyableTypes(string path);

/** A path an `allowCopyableTypes` row names. */
private class CopyableType extends ModelPath {
  CopyableType() { allowCopyableTypes(this) }
}

/**
 * Holds if `n` resolves to a `Copy` type, so moving it leaves the original
 * behind.
 */
predicate copyTyped(AstNode n) {
  arrayTyped(n)
  or
  hasTrait(inferredItem(n), "Copy")
  or
  inferredItem(n) = itemOf(any(CopyableType p))
}
