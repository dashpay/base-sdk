//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared helpers.

#![allow(dead_code, reason = "usage dependent on build flags")]
#![expect(clippy::unwrap_used, clippy::panic, reason = "test code")]

#[cfg(feature = "bls")]
pub mod bls;

/// Raw JSON file, a map of sub-operation names to arrays or objects.
pub type VectorFile = serde_json::Value;

/// Load a vector file from tests/corpus/.
pub fn load(name: &str) -> VectorFile {
  let path = format!("{}/corpus/{}.json", env!("CARGO_MANIFEST_DIR"), name);
  let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
  serde_json::from_str(&data).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"))
}

/// Extract a sub-operation's vector array and deserialize it.
pub fn parse_sub<T: serde::de::DeserializeOwned>(file: &VectorFile, key: &str) -> Vec<T> {
  let arr = file
    .get(key)
    .unwrap_or_else(|| panic!("missing key '{key}' in vector file"));
  serde_json::from_value(arr.clone()).unwrap_or_else(|e| panic!("cannot parse '{key}': {e}"))
}

pub fn hash_from_hex(s: &str) -> dash_num::Hash256 {
  dash_num::Hash256::from_hex(s).unwrap()
}

pub fn make_id(i: u32) -> dash_num::Hash256 {
  let mut bytes = [0u8; 32];
  bytes[28..32].copy_from_slice(&i.to_be_bytes());
  dash_num::Hash256::from_bytes(bytes)
}

pub fn sequential_ids(n: usize) -> Vec<dash_num::Hash256> {
  (1..=n).map(|i| make_id(i as u32)).collect()
}

/// Shared test constants.
pub const MSG_DEADBEEF: [u8; 32] = hex_literal::hex!(
  "deadbeefdeadbeefdeadbeefdeadbeef"
  "cafebabecafebabecafebabecafebabe"
);
