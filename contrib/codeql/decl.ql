/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/decl-rules
 * @name Rules for definition orders
 * @description Enforces order of definitions for enums, impls and structs.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags style
 */

import lib.filters
import lib.fmt
import lib.policy
import rust

predicate outOfOrder(TypeItem t, int badSlot, int badLine, int priorSlot, Locatable badItem) {
  exists(int priorLine |
    itemEntry(t, priorSlot, priorLine, _) and
    itemEntry(t, badSlot, badLine, badItem) and
    badSlot < priorSlot and
    badLine > priorLine and
    // A macro can emit items spanning several slots on the same
    // line.  Suppress when the earlier line also contains an item
    // at or below badSlot: the bad item is correctly positioned
    // relative to that lower-slot companion.
    not exists(int colocatedSlot |
      itemEntry(t, colocatedSlot, priorLine, _) and
      colocatedSlot <= badSlot
    )
  )
}

from TypeItem t, Locatable badItem, string name, string message
where
  isSourceType(t) and
  (t instanceof Struct or t instanceof Enum) and
  not isSerdeInternalType(t) and
  not isNotEncodable(t) and
  isEvaluatedCrate(fileOf(t)) and
  name = t.getName().getText() and
  exists(int badSlot, int badLine, int priorSlot |
    outOfOrder(t, badSlot, badLine, priorSlot, badItem) and
    message =
      fmt("{0} {1} appears after {2}", name,
        fmt("{0} (slot {1})", slotLabel(badSlot), badSlot.toString()),
        fmt("{0} (slot {1})", slotLabel(priorSlot), priorSlot.toString()))
  )
select badItem, message
