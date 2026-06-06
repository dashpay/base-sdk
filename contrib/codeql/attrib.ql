/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @name Attribute and derivation rules
 * @description Enforcement of required traits per feasible type.
 * @kind problem
 * @problem.severity warning
 * @id base-sdk/attrib-rules
 * @tags style
 * @precision high
 */

import lib.filters
import lib.fmt
import lib.policy
import lib.traits
import rust

/** Gets a comma-separated list of missing required traits for `t`. */
string missingTraits(TypeItem t) {
  isCheckableType(t) and
  result =
    concat(string trait |
      trait = requiredTrait() and
      not implementsTrait(t, trait) and
      not isSuppressed(t, trait)
    |
      trait, ", " order by trait
    ) and
  result != ""
}

from TypeItem t, string message
where
  isCheckableType(t) and
  (
    exists(string missing |
      missing = missingTraits(t) and
      message = fmt("missing required derivations: {0}", missing)
    )
    or
    // Serde: every non-exempt type must derive Serialize + Deserialize.
    not isSerdeExempt(t) and
    exists(string missing |
      missing =
        concat(string trait |
          trait = requiredSerdeTrait() and
          not implementsSerdeTrait(t, trait)
        |
          trait, ", " order by trait
        ) and
      missing != "" and
      message = fmt("missing serde derivations: {0}", missing)
    )
  )
select t, message
