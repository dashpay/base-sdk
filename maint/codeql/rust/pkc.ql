/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/pkc-rules
 * @name Rules for dash-pkc
 * @description The arms must offer the same operations and carry the same traits.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags maintainability
 */

import lib.filters
import lib.fmt
import lib.policy
import lib.pkc
import lib.traits
import rust

/**
 * Holds if `t` is `arm`'s type for `role`, split off the name rather than the
 * module so that every arm naming a role holds the same one. A role only one
 * arm holds never pairs, and reports nothing.
 */
predicate armRole(TypeItem t, string arm, string role) {
  isSourceType(t) and
  isEnforcedCrate(fileOf(t)) and
  exists(string name |
    name = nameOf(t) and
    arm = name.regexpCapture("^(Bls|Ecdsa|Eddsa)([A-Z].*)$", 1) and
    role = name.regexpCapture("^(Bls|Ecdsa|Eddsa)([A-Z].*)$", 2)
  )
}

/** Holds if `f` is `pub`, rather than restricted to a scope. */
predicate isBarePub(Function f) {
  exists(f.getVisibility()) and
  not exists(f.getVisibility().getPath())
}

/**
 * Holds if `t` offers `name` as a public inherent method.
 *
 * Matched wherever the impl sits, not through `inherentImpl`, which the
 * declaration order rule needs to be file-local; an arm spreads a type's
 * methods over several modules.
 *
 * Macro-written impls are skipped, since what a macro grants a type follows
 * from which macro it expands rather than from the arm.
 */
predicate publicMethod(TypeItem t, string name) {
  exists(Impl i, Function f |
    not exists(MacroItems m | i = m.getItem(_)) and
    implSelfName(i) = nameOf(t) and
    not exists(implTraitName(i)) and
    isEnforcedCrate(fileOf(i)) and
    f = i.getAssocItemList().getAnAssocItem() and
    isBarePub(f) and
    not isTestCode(f) and
    name = nameOf(f)
  )
}

/**
 * Holds if `lacks` is missing `name`, which `arm` offers for the same role.
 */
predicate shapeGap(TypeItem lacks, string role, string name, string arm) {
  exists(TypeItem offers, string lacking |
    armRole(offers, arm, role) and
    armRole(lacks, lacking, role) and
    lacking != arm and
    publicMethod(offers, name) and
    not publicMethod(lacks, name) and
    not armOnly(arm, role, name) and
    not armLacks(lacking, role, name)
  )
}

/**
 * Holds if `lacks` is missing `trait`, which `arm` carries for the same role
 * inclusive of derives gated by `cfg_attr`.
 *
 * Double-underscore traits are skipped, considered private implementation
 * concerns not part of the public API.
 */
predicate traitGap(TypeItem lacks, string role, string trait, string arm) {
  exists(TypeItem offers, string lacking |
    armRole(offers, arm, role) and
    armRole(lacks, lacking, role) and
    lacking != arm and
    not trait.matches("\\_\\_%") and
    implementsPlainTrait(offers, trait) and
    not implementsPlainTrait(lacks, trait) and
    not hasDerive(lacks, trait) and
    not armLacksTrait(lacking, role, trait)
  )
}

from TypeItem t, string message
where
  exists(string role, string name, string arm |
    shapeGap(t, role, name, arm) and
    message = fmt("{0} offers {1}, {2} does not", arm + role, fmt("{0}()", name), nameOf(t))
  )
  or
  exists(string role, string trait, string arm |
    traitGap(t, role, trait, arm) and
    message = fmt("{0} implements {1}, {2} does not", arm + role, trait, nameOf(t))
  )
select t, message
