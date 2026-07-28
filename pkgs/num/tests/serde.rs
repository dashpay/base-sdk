//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Serde roundtrip tests for all types.

use dash_dev::{assert_json_rt, from_json, json_rejects, to_json};
use dash_num::{Arith256, CompactTarget, Hash160, Hash256, Hash512};
use hex_literal::hex;

#[test]
fn hash256_json_roundtrip() {
  let bytes = hex!("9c524adbcf5611122b29125e5d35d2d22281aab533f00832d556b1f9eae51d7d");
  let h = Hash256::from_bytes(bytes);
  assert_json_rt(&h);

  assert_json_rt(&Hash256::ZERO);
  assert_json_rt(&Hash256::from_bytes([0xff; 32]));
}

#[test]
fn hash160_json_roundtrip() {
  let bytes = hex!("0102030405060708090a0b0c0d0e0f1011121314");
  let h = Hash160::from_bytes(bytes);
  assert_json_rt(&h);
  assert_json_rt(&Hash160::ZERO);
}

#[test]
fn hash512_json_roundtrip() {
  let mut bytes = [0u8; 64];
  bytes[0] = 0x42;
  bytes[63] = 0xff;
  let h = Hash512::from_bytes(bytes);
  assert_json_rt(&h);
  assert_json_rt(&Hash512::ZERO);
}

#[test]
fn arith256_json_roundtrip() {
  let check = |uint: Arith256, hex: &str| {
    let json = format!("\"{}\"", hex);
    assert_eq!(to_json(&uint), json);
    assert_eq!(from_json::<Arith256>(&json), uint);
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
  assert!(json_rejects::<Arith256>(
    "\"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffg\""
  ));
  // Odd length
  assert!(json_rejects::<Arith256>(
    "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffx\""
  ));
  // Too long
  assert!(json_rejects::<Arith256>(
    "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
  ));
}

#[test]
fn compact_target_json_roundtrip() {
  assert_json_rt(&CompactTarget(0));
  assert_json_rt(&CompactTarget(0x1d00ffff));
  assert_json_rt(&CompactTarget(0x0412_3456));
}
