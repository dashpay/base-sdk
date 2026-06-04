/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Rule-specific policy predicates for type classification.
 */

import lib.files
import rust

/** Holds if `t` holds secret or security-sensitive material. */
predicate isSecretType(TypeItem t) {
  t.getName().getText().regexpMatch(".*(Secret|Private|Seed|Password|Mnemonic|Share).*") and
  // Exclude types whose name contains "Shared" (e.g. SharedState),
  // which match the Share substring but are not secret holders.
  not t.getName().getText().regexpMatch(".*Shared.*")
}

/** Holds if `u` imports directly from `alloc` outside `prelude.rs`. */
predicate directAllocImport(Use u) {
  usePrefix(u) = "alloc" and
  not fileOf(u).getBaseName() = "prelude.rs" and
  not fileOf(u).getAbsolutePath().matches("%/prelude/mod.rs")
}
