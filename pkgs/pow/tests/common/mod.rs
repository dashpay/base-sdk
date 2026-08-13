//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared NIST KAT helpers.

#![allow(dead_code, reason = "usage dependent on build flags")]

use dash_dev::{arr_from_hex, Corpus};

const NIST_MSG_BLOB: &[u8] = include_bytes!("../../corpus/nist_msg.bin");

/// Returns the NIST test message of `byte_len` bytes.
///
/// The message blob contains messages of length 0..=255 bytes, laid out at
/// triangular offsets so each message is uniquely determined by its length.
pub fn nist_input(byte_len: usize) -> &'static [u8] {
  assert!(byte_len <= 255, "byte_len must be <= 255");
  let off = byte_len.wrapping_mul(byte_len.wrapping_sub(1)) / 2;
  &NIST_MSG_BLOB[off..off + byte_len]
}

/// Expected digests indexed by input length, as hex.
pub type NistVectors = Vec<String>;

/// Loads a corpus file by name and returns the parsed vectors.
pub fn load(name: &str) -> NistVectors {
  Corpus::open(env!("CARGO_MANIFEST_DIR"), name).vectors("nist")
}

/// Runs all NIST KAT vectors for a given hash function.
pub fn run_nist_kat(name: &str, vectors: &NistVectors, hash_fn: fn(&[u8]) -> [u8; 64]) {
  for (byte_len, digest) in vectors.iter().enumerate() {
    let input = nist_input(byte_len);
    let expected: [u8; 64] = arr_from_hex(digest);
    let got = hash_fn(input);
    assert_eq!(got, expected, "{name}: mismatch at byte_len={byte_len}");
  }
}
