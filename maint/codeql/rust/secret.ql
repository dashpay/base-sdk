/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/secret-rules
 * @name Secret material handling rules
 * @description Secret types must erase themselves, redact, compare in constant
 *              time and stay off growable buffers.
 * @kind problem
 * @precision high
 * @problem.severity error
 * @tags security
 */

import lib.crates
import lib.fmt
import lib.policy
import lib.secret
import lib.traits
import rust

/** The secret handling policy of this workspace. */
module Policy implements SecretPolicySig {
  predicate secretByName(TypeItem t) { isSecretType(t) }

  predicate enforcedFile(File f) { isEnforcedCrate(f) }
}

module Secrets = Secret<Policy>;

/**
 * Holds if `t` reaches the wire through the erasing encoder.
 *
 * `impl_stype!` and `impl_sbytes!` emit `type Encoder = ArrEncoder<N>`. The
 * plain `impl_type!` and `impl_bytes!` emit `type Encoder = VecEncoder`.
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
 * Holds if `t` is an encodable secret on growable storage.
 *
 * That storage can reallocate mid-write and strand a copy that the erase never
 * reaches.
 */
predicate growableSecret(TypeItem t) {
  Secrets::enforcedSecretType(t) and
  not isNotEncodable(t) and
  growableType(fieldTypeRepr(t))
}

/** Holds if `t` reaches the wire through an encoder that does not erase. */
predicate leakySecretBridge(TypeItem t) {
  Secrets::enforcedSecretType(t) and
  implementsTrait(t, "Encodable") and
  not usesSecretBridge(t)
}

from Locatable e, string message
where
  Secrets::unwipedSecret(e) and message = "secret type is never wiped"
  or
  exists(string cause | Secrets::unredactedSecret(e, cause) |
    message = fmt("secret type {0}", cause)
  )
  or
  exists(string retType | Secrets::leakedWipedBytes(e, retType) |
    message = fmt("wiping function returns bare {0}", retType)
  )
  or
  growableSecret(e) and message = "encodable secret type is backed by a growable buffer"
  or
  leakySecretBridge(e) and message = "secret wire type stages through a non-wiping encoder"
  or
  Secrets::variableTimeSecretEq(e) and message = "secret type compares in variable time"
  or
  exists(string how | Secrets::variableTimeSecretTest(e, how) |
    message = fmt("secret type test uses {0}, which stops early", how)
  )
select e, message
