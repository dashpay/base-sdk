/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Rule-specific policy predicates for type classification.
 */

import lib.files
import lib.filters
import lib.source_lines
import lib.traits
import rust

/** Folds the derive token text extraction for join efficiency. */
pragma[nomagic]
private predicate deriveTokenText(TypeItem t, string text) {
  exists(Attr a |
    a = t.getAnAttr() and
    a.getMeta().getPath().getSegment().getIdentifier().getText() = "derive" and
    text = a.getMeta().getTokenTree().toAbbreviatedString()
  )
}

/** Holds if `t` carries `#[derive(Unencodable)]` or `#[derive(dash_types::Unencodable)]`. */
predicate isNotEncodable(TypeItem t) {
  exists(string text |
    deriveTokenText(t, text) and
    text.regexpMatch(".*\\bUnencodable\\b.*")
  )
}

/** Holds if `t` holds secret or security-sensitive material. */
predicate isSecretType(TypeItem t) {
  t.getName().getText().regexpMatch(".*(Secret|Private|Seed|Password|Mnemonic|Share).*") and
  // Exclude types whose name contains "Shared" (e.g. SharedState),
  // which match the Share substring but are not secret holders.
  not t.getName().getText().regexpMatch(".*Shared.*")
}

/** Holds if `t` is an iterator type (name ends with Iterator or Iter). */
predicate isIteratorType(TypeItem t) {
  t.getName().getText().matches("%Iterator") or
  t.getName().getText().matches("%Iter")
}

/** Holds if `t` is an error type (name ends with Error, Invalid, TooLong, or TooShort). */
predicate isErrorType(TypeItem t) {
  t.getName().getText().matches("%Error") or
  t.getName().getText().matches("%Invalid") or
  t.getName().getText().matches("%TooLong") or
  t.getName().getText().matches("%TooShort")
}

/** Holds if `t` is a dispatch/message type (name ends with Message). */
predicate isDispatchType(TypeItem t) { t.getName().getText().matches("%Message") }

/** Holds if `t` is an opaque single-field wrapper in the pkc crate. */
predicate isOpaqueType(TypeItem t) {
  t instanceof Struct and
  exists(string path |
    path = fileOf(t).getAbsolutePath() and
    path.matches("%/pkgs/pkc/%")
  ) and
  isSingleTupleField(t)
}

/** Materialises (TypeItem, fieldTypeName, crate) for join efficiency. */
pragma[nomagic]
private predicate fieldTypeInCrate(TypeItem t, string fieldTypeName, string crate) {
  fieldTypeName = typeFieldName(t) and crate = cratePrefix(t)
}

/** Materialises (TypeItem, name, crate) for join efficiency. */
pragma[nomagic]
private predicate typeNameInCrate(TypeItem t, string name, string crate) {
  name = t.getName().getText() and crate = cratePrefix(t)
}

/** Holds if struct `s` contains a float field, directly or transitively. */
predicate hasFloatField(TypeItem t) {
  typeFieldName(t) = ["f32", "f64"]
  or
  exists(TypeItem inner, string name, string crate |
    fieldTypeInCrate(t, name, crate) and
    typeNameInCrate(inner, name, crate) and
    hasFloatField(inner)
  )
}

/**
 * Holds if `t` is a serde internal generated type
 * (e.g. __FieldVisitor, __Visitor, __Field).
 */
predicate isSerdeInternalType(TypeItem t) { t.getName().getText().matches("\\_\\_%") }

/** Gets a required trait name. */
string requiredTrait() { result = ["Clone", "Debug", "Eq", "Hash", "PartialEq"] }

/** Gets a required serde trait name. */
string requiredSerdeTrait() { result = ["Serialize", "Deserialize"] }

/** Holds if `t` is codec infrastructure (decoder or encoder wrappers). */
predicate isCodecType(TypeItem t) {
  t.getName().getText().matches("%Decoder%") or
  t.getName().getText().matches("%Encoder%")
}

/** Holds if `t` is a source type eligible for the "must derive" check. */
predicate isCheckableType(TypeItem t) {
  isSourceType(t) and
  not isSerdeInternalType(t) and
  not isCodecType(t) and
  not isSecretType(t) and
  not isIteratorType(t)
}

/** Holds if `t` lives in a crate that does not have a `serde` feature. */
predicate isNonSerdeCrate(TypeItem t) {
  exists(string path |
    path = fileOf(t).getAbsolutePath() and
    (path.matches("%/pkgs/params/%") or path.matches("%/pkgs/pow/%"))
  )
}

/** Materialises the regex capture for file-relative paths. */
pragma[nomagic]
private predicate fileRelPath(File f, string relPath) {
  relPath = f.getAbsolutePath().regexpCapture(".*/pkgs/(.*)", 1)
}

/**
 * Holds if `t` implements a serde trait via crate-qualified impl
 * or a cfg_attr/cfg gate that mentions serde.
 */
bindingset[traitName]
predicate implementsSerdeTrait(TypeItem t, string traitName) {
  implementsTraitInCrate(t, traitName, "serde")
  or
  exists(Attr a, int serdeLine, string relPath |
    a = t.getAnAttr() and
    a.getMeta().getPath().getSegment().getIdentifier().getText() = ["cfg_attr", "cfg"] and
    fileRelPath(fileOf(t), relPath) and
    hasSerdeMention(relPath, serdeLine, traitName) and
    serdeLine >= a.getLocation().getStartLine() and
    serdeLine <= a.getLocation().getEndLine()
  )
}

/**
 * Holds when `trait` should not be required for `t`.
 */
predicate isSuppressed(TypeItem t, string trait) {
  // Float types: suppress Eq and Hash
  hasFloatField(t) and trait = ["Eq", "Hash"]
  or
  // Error types: suppress Hash
  isErrorType(t) and trait = "Hash"
  or
  // Dispatch types: suppress Hash
  isDispatchType(t) and trait = "Hash"
  or
  // Opaque types: suppress Hash
  isOpaqueType(t) and trait = "Hash"
}

/** Holds if `t` is exempt from serde derivation requirements. */
predicate isSerdeExempt(TypeItem t) {
  isNonSerdeCrate(t)
  or
  isNotEncodable(t)
  or
  isCodecType(t)
  or
  isErrorType(t)
  or
  isDispatchType(t)
  or
  isOpaqueType(t)
  or
  hasLifetime(t)
  or
  // Single-field wrappers without PartialEq are exempt.
  isSingleTupleField(t) and
  not implementsTrait(t, "PartialEq")
}

/** Holds if `u` imports directly from `alloc` outside `prelude.rs`. */
predicate directAllocImport(Use u) {
  usePrefix(u) = "alloc" and
  not fileOf(u).getBaseName() = "prelude.rs" and
  not fileOf(u).getAbsolutePath().matches("%/prelude/mod.rs")
}
