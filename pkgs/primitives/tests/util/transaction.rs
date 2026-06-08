//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction-specific corpus test utilities.

use super::{load_section, CorpusEntry};

use dash_primitives::Transaction;

use std::collections::BTreeMap;

/// Verifies that wire-decoded and deserialized forms agree
/// for every entry in a corpus section, then serde round-trips.
pub fn check(file: &str, section: &str) {
  let corpus: BTreeMap<String, CorpusEntry<Transaction>> = load_section(file, section);
  assert!(!corpus.is_empty());
  for (label, entry) in &corpus {
    super::assert_txid(&entry.raw, label);
    let lhs = super::decode_tx(&entry.raw);
    let rhs = &entry.details;
    assert_eq!(lhs, *rhs, "{file}/{section}/{label}");
    let json = serde_json::to_string(&lhs).unwrap();
    let round_tripped: Transaction = serde_json::from_str(&json).unwrap();
    assert_eq!(lhs, round_tripped, "serde round-trip: {file}/{section}/{label}");
    super::assert_round_trip(&entry.raw, &lhs, label);
  }
}
