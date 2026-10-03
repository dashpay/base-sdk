/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/zeroize-rules
 * @name Secret material handling rules
 * @description Secret types must wipe, redact, and stay off growable buffers.
 * @kind problem
 * @precision high
 * @problem.severity error
 * @tags security
 */

import lib.filters
import lib.fmt
import lib.policy
import lib.secret
import lib.traits
import rust

/**
 * Holds if `t` reaches the wire through the wiping encoder pair.
 *
 * `impl_stype!`/`impl_sbytes!` emit `type Encoder = ArrEncoder<N>`; the plain
 * `impl_type!`/`impl_bytes!` emit `type Encoder = VecEncoder`.
 */
predicate usesSecretBridge(TypeItem t) {
  exists(Impl i, TypeAlias ta |
    i.getSelf() = t and
    implTraitName(i) = "Encodable" and
    ta = implItem(i) and
    nameOf(ta) = "Encoder" and
    typeHead(ta.getTypeRepr()) = "ArrEncoder"
  )
}

/**
 * Holds if `t` is an encodable secret on growable storage, which can
 * reallocate mid-write and strand a copy the wipe never reaches.
 */
predicate growableSecret(TypeItem t) {
  enforcedSecretType(t) and
  not isNotEncodable(t) and
  isGrowableType(fieldTypeRepr(t))
}

/** Holds if `t` reaches the wire through an encoder that does not wipe. */
predicate leakySecretBridge(TypeItem t) {
  enforcedSecretType(t) and
  implementsTrait(t, "Encodable") and
  not usesSecretBridge(t)
}

from Locatable e, string message
where
  unwipedSecret(e) and message = "secret type is never wiped"
  or
  exists(string cause | unredactedSecret(e, cause) | message = fmt("secret type {0}", cause))
  or
  exists(string retType | leakedWipedBytes(e, retType) |
    message = fmt("wiping function returns bare {0}", retType)
  )
  or
  growableSecret(e) and message = "encodable secret type is backed by a growable buffer"
  or
  leakySecretBridge(e) and message = "secret wire type stages through a non-wiping encoder"
  or
  variableTimeSecretEq(e) and message = "secret type compares in variable time"
  or
  exists(string how | variableTimeSecretTest(e, how) |
    message = fmt("secret type test uses {0}, which stops early", how)
  )
select e, message
