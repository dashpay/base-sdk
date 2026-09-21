/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description AST node accessors and navigation.
 */

import lib.files
import rust
private import codeql.rust.internal.typeinference.Type as T
private import codeql.rust.internal.typeinference.TypeMention

/**
 * An item that carries a name.
 */
class Named extends Item {
  Named() {
    this instanceof TypeItem or
    this instanceof Function or
    this instanceof Trait or
    this instanceof Module or
    this instanceof TypeAlias
  }

  /** Gets this item's name. */
  string getNameText() {
    result = this.(TypeItem).getName().getText() or
    result = this.(Function).getName().getText() or
    result = this.(Trait).getName().getText() or
    result = this.(Module).getName().getText() or
    result = this.(TypeAlias).getName().getText()
  }
}

/** Gets the name of `n`. */
string nameOf(Named n) { result = n.getNameText() }

/**
 * Holds if `v` is a bare `pub`. A scoped `pub(crate)` or `pub(super)` carries
 * a path while bare `pub` does not.
 */
predicate isBarePublic(Visibility v) { not exists(v.getPath()) }

/** Gets the identifier of `p`'s final segment, e.g. `c` for `a::b::c`. */
string pathName(Path p) { result = p.getSegment().getIdentifier().getText() }

/** Gets the identifier of `p`'s qualifier, e.g. `b` for `a::b::c`. */
string pathQualifierName(Path p) { result = pathName(p.getQualifier()) }

/** Gets an attribute of a preamble item (Use, Module, or ExternCrate). */
private Attr itemAttr(Item item) {
  result = item.(Use).getAnAttr() or
  result = item.(Module).getAnAttr() or
  result = item.(ExternCrate).getAnAttr()
}

/**
 * Gets the effective start line of `item`, accounting for leading
 * attributes (e.g. `#[cfg(...)]`).
 */
int effectiveStart(Item item) {
  if exists(itemAttr(item))
  then result = min(Attr a | a = itemAttr(item) | startLine(a))
  else result = startLine(item)
}

/** Gets the root (qualifier-less) segment of path `p`. */
private Path rootPath(Path p) {
  result = p.getQualifier*() and
  not exists(result.getQualifier())
}

/** Holds if module `m` is not nested inside another module. */
predicate isRootModule(Module m) {
  not exists(Module enclosing | m.getParentNode() = enclosing.getItemList())
}

/** Gets the first path segment of use declaration `u`. */
string usePrefix(Use u) { result = pathName(rootPath(u.getUseTree().getPath())) }

/** Gets the head identifier of `tr`, e.g. `Vec` for `Vec<u8>`. */
string typeHead(TypeRepr tr) { result = pathName(tr.(PathTypeRepr).getPath()) }

/** Gets the type item `tr` names, resolved through the type layer. */
TypeItem namedTypeItem(TypeRepr tr) {
  result = tr.(TypeMention).getType().(T::DataType).getTypeItem()
}

/** Gets the declared type of a field of `t`, including enum variant fields. */
TypeRepr fieldTypeRepr(TypeItem t) {
  result = t.(Struct).getFieldList().(StructFieldList).getAField().getTypeRepr()
  or
  result = t.(Struct).getFieldList().(TupleFieldList).getField(_).getTypeRepr()
  or
  result = t.(Union).getStructFieldList().getAField().getTypeRepr()
  or
  exists(Variant v |
    v = t.(Enum).getVariantList().getAVariant() and
    (
      result = v.getFieldList().(StructFieldList).getAField().getTypeRepr() or
      result = v.getFieldList().(TupleFieldList).getField(_).getTypeRepr()
    )
  )
}
