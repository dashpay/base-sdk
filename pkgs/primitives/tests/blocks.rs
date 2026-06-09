//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for full block decode/encode.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use dash_primitives::{Block, BlockHash, MerkleRoot};
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_blocks();
  for (block_hash_hex, entry) in &corpus {
    let raw = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let block: Block = decode_from_slice(&raw).unwrap();
    assert!(block.validate().is_ok());

    let h = &entry.header;
    let body = &entry.body;

    assert_eq!(
      block.header.version,
      util::json_u64(&h["version"]) as i32,
      "{block_hash_hex} version",
    );
    assert_eq!(
      block.header.prev_hash,
      BlockHash::from_hex(util::json_str(&h["previousblockhash"])).unwrap(),
      "{block_hash_hex} prev_hash",
    );
    assert_eq!(
      block.header.merkle_root,
      MerkleRoot::from_hex(util::json_str(&h["merkleroot"])).unwrap(),
      "{block_hash_hex} merkle_root",
    );
    assert_eq!(
      block.header.time,
      util::json_u64(&h["time"]) as u32,
      "{block_hash_hex} time",
    );
    assert_eq!(
      block.header.bits,
      u32::from_str_radix(util::json_str(&h["bits"]), 16).unwrap(),
      "{block_hash_hex} bits",
    );
    assert_eq!(
      block.header.nonce,
      util::json_u64(&h["nonce"]) as u32,
      "{block_hash_hex} nonce",
    );

    assert_eq!(
      block.transactions.len(),
      util::json_u64(&body["nTx"]) as usize,
      "{block_hash_hex} nTx",
    );

    let expected_txids = body["tx"].as_array().unwrap();
    for (i, expected) in expected_txids.iter().enumerate() {
      let tx_bytes = encode_to_vec(&block.transactions[i]);
      let computed = dash_primitives::hash::tx_hash(&tx_bytes);
      let expected_hash = dash_primitives::TxHash::from_hex(util::json_str(expected)).unwrap();
      assert_eq!(computed, expected_hash, "{block_hash_hex} tx[{i}]");
    }
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_blocks();
  for (block_hash_hex, entry) in &corpus {
    let raw = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let block: Block = decode_from_slice(&raw).unwrap();
    let encoded = encode_to_vec(&block);
    assert_eq!(encoded, raw, "{block_hash_hex} round-trip");
  }
}

#[rstest]
fn block_hash() {
  let corpus = util::load_blocks();
  for (block_hash_hex, entry) in &corpus {
    let raw = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let pow_hash = BlockHash::from(dash_pow::hash(&raw[..80]));
    let expected = BlockHash::from_hex(block_hash_hex).unwrap();
    assert_eq!(pow_hash, expected, "{block_hash_hex} hash");
  }
}
