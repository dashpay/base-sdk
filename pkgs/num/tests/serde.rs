//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Serde and bincode roundtrip tests for all types.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_num::{Arith256, CompactTarget, Hash160, Hash256, Hash512};
use hex_literal::hex;

fn json_roundtrip<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug>(val: &T) {
  let json = serde_json::to_string(val).unwrap();
  let decoded: T = serde_json::from_str(&json).unwrap();
  assert_eq!(&decoded, val);
}

fn bincode_roundtrip<T: bincode::Encode + bincode::Decode<()> + PartialEq + core::fmt::Debug>(val: &T) {
  let config = bincode::config::standard();
  let bin = bincode::encode_to_vec(val, config).unwrap();
  let (decoded, _): (T, _) = bincode::decode_from_slice(&bin, config).unwrap();
  assert_eq!(&decoded, val);
}

#[test]
fn hash256_json_roundtrip() {
  let bytes = hex!("9c524adbcf5611122b29125e5d35d2d22281aab533f00832d556b1f9eae51d7d");
  let h = Hash256::from_bytes(bytes);
  json_roundtrip(&h);

  json_roundtrip(&Hash256::ZERO);
  json_roundtrip(&Hash256::from_bytes([0xff; 32]));
}

#[test]
fn hash256_bincode_roundtrip() {
  let bytes = hex!("9c524adbcf5611122b29125e5d35d2d22281aab533f00832d556b1f9eae51d7d");
  let h = Hash256::from_bytes(bytes);
  bincode_roundtrip(&h);

  bincode_roundtrip(&Hash256::ZERO);
}

#[test]
fn hash160_json_roundtrip() {
  let bytes = hex!("0102030405060708090a0b0c0d0e0f1011121314");
  let h = Hash160::from_bytes(bytes);
  json_roundtrip(&h);
  json_roundtrip(&Hash160::ZERO);
}

#[test]
fn hash160_bincode_roundtrip() {
  let bytes = hex!("0102030405060708090a0b0c0d0e0f1011121314");
  let h = Hash160::from_bytes(bytes);
  bincode_roundtrip(&h);
}

#[test]
fn hash512_json_roundtrip() {
  let mut bytes = [0u8; 64];
  bytes[0] = 0x42;
  bytes[63] = 0xff;
  let h = Hash512::from_bytes(bytes);
  json_roundtrip(&h);
  json_roundtrip(&Hash512::ZERO);
}

#[test]
fn hash512_bincode_roundtrip() {
  let mut bytes = [0u8; 64];
  bytes[0] = 0x42;
  bytes[63] = 0xff;
  let h = Hash512::from_bytes(bytes);
  bincode_roundtrip(&h);
}

#[test]
fn arith256_json_roundtrip() {
  let check = |uint: Arith256, hex: &str| {
    let json = format!("\"{}\"", hex);
    assert_eq!(serde_json::to_string(&uint).unwrap(), json);
    assert_eq!(serde_json::from_str::<Arith256>(&json).unwrap(), uint);
  };

  check(
    Arith256::ZERO,
    "0000000000000000000000000000000000000000000000000000000000000000",
  );
  check(
    Arith256::from(0xDEADBEEF_u32),
    "00000000000000000000000000000000000000000000000000000000deadbeef",
  );
  check(
    Arith256::MAX,
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  );
}

#[test]
fn arith256_json_invalid() {
  // Invalid char
  assert!(
    serde_json::from_str::<Arith256>("\"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffg\"").is_err()
  );
  // Odd length
  assert!(
    serde_json::from_str::<Arith256>("\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffx\"").is_err()
  );
  // Too long
  assert!(
    serde_json::from_str::<Arith256>("\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"").is_err()
  );
}

#[test]
fn arith256_bincode_roundtrip() {
  bincode_roundtrip(&Arith256::ZERO);
  bincode_roundtrip(&Arith256::ONE);
  bincode_roundtrip(&Arith256::MAX);
  bincode_roundtrip(&Arith256::from(0xDEADBEEF_u64));
}

#[test]
fn compact_target_json_roundtrip() {
  json_roundtrip(&CompactTarget(0));
  json_roundtrip(&CompactTarget(0x1d00ffff));
  json_roundtrip(&CompactTarget(0x0412_3456));
}

#[test]
fn compact_target_bincode_roundtrip() {
  bincode_roundtrip(&CompactTarget(0));
  bincode_roundtrip(&CompactTarget(0x1d00ffff));
  bincode_roundtrip(&CompactTarget(0x0412_3456));
}
