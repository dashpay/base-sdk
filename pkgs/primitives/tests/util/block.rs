//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block-specific corpus test utilities.

use super::{load_section, CorpusEntry};

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use dash_primitives::{Block, BlockHash};
use hex_conservative::FromHex;

use std::collections::BTreeMap;

/// Verifies that wire-decoded and deserialized block forms agree
/// for every entry in the block corpus, then serde and binary
/// round-trips. Also checks the PoW block hash.
pub fn check() {
  let corpus: BTreeMap<String, CorpusEntry<Block>> = load_section("blocks", "blocks");
  assert!(!corpus.is_empty());
  for (block_hash_hex, entry) in &corpus {
    let raw = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let lhs: Block = decode_from_slice(&raw).unwrap();
    let rhs = &entry.details;
    assert_eq!(lhs, *rhs, "blocks/{block_hash_hex}");

    let json = serde_json::to_string(&lhs).unwrap();
    let round_tripped: Block = serde_json::from_str(&json).unwrap();
    assert_eq!(lhs, round_tripped, "serde round-trip: blocks/{block_hash_hex}");

    let encoded = encode_to_vec(&lhs);
    assert_eq!(encoded, raw, "binary round-trip: blocks/{block_hash_hex}");

    let pow_hash = BlockHash::from(dash_pow::hash(&raw[..80]));
    let expected = BlockHash::from_hex(block_hash_hex).unwrap();
    assert_eq!(pow_hash, expected, "pow hash: blocks/{block_hash_hex}");
  }
}
