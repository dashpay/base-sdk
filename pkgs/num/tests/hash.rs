//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hash type conformance tests.

#![expect(clippy::unwrap_used, reason = "test code")]

use dash_num::{Hash160, Hash256, ParseHexError};
use dash_types::Numeric;
use hex_literal::hex;
use rstest::*;

use core::str::FromStr;

/// Consensus test vector R1 (raw little-endian bytes).
#[fixture]
fn r1_bytes() -> [u8; 32] {
  hex!("9c524adbcf5611122b29125e5d35d2d22281aab533f00832d556b1f9eae51d7d")
}

/// Consensus test vector R1 (big-endian hex display).
#[fixture]
fn r1_hex() -> &'static str {
  "7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c"
}

/// Consensus test vector R2 (raw little-endian bytes).
#[fixture]
fn r2_bytes() -> [u8; 32] {
  hex!("70321d7c47a56b40267e0ac3a69cb6bf133047a3192dda71491372f0b4ca81d7")
}

/// Consensus test vector R2 (big-endian hex display).
#[fixture]
fn r2_hex() -> &'static str {
  "d781cab4f072134971da2d19a3473013bfb69ca6c30a7e26406ba5477c1d3270"
}

const ONE_ARRAY: [u8; 32] = {
  let mut a = [0u8; 32];
  a[0] = 1;
  a
};

#[rstest]
fn from_bytes_to_hex(r1_bytes: [u8; 32], r1_hex: &str, r2_bytes: [u8; 32], r2_hex: &str) {
  assert_eq!(format!("{}", Hash256::from_bytes(r1_bytes)), r1_hex);
  assert_eq!(format!("{}", Hash256::from_bytes(r2_bytes)), r2_hex);
}

#[rstest]
fn from_hex_to_bytes(r1_bytes: [u8; 32], r1_hex: &str, r2_bytes: [u8; 32], r2_hex: &str) {
  assert_eq!(Hash256::from_hex(r1_hex).unwrap().to_bytes(), r1_bytes);
  assert_eq!(Hash256::from_hex(r2_hex).unwrap().to_bytes(), r2_bytes);
}

#[rstest]
fn roundtrip_hex(r1_bytes: [u8; 32], r2_bytes: [u8; 32]) {
  let r1 = Hash256::from_bytes(r1_bytes);
  assert_eq!(Hash256::from_str(&format!("{r1}")).unwrap(), r1);

  let r2 = Hash256::from_bytes(r2_bytes);
  assert_eq!(Hash256::from_str(&format!("{r2}")).unwrap(), r2);
}

#[rstest]
fn roundtrip_bytes(r1_bytes: [u8; 32], r2_bytes: [u8; 32]) {
  assert_eq!(Hash256::from_bytes(r1_bytes).to_bytes(), r1_bytes);
  assert_eq!(Hash256::from_bytes(r2_bytes).to_bytes(), r2_bytes);
}

#[rstest]
fn zero_one_max() {
  assert_eq!(Hash256::ZERO.to_bytes(), [0u8; 32]);
  assert!(Hash256::ZERO.is_null());

  let one = Hash256::from_bytes(ONE_ARRAY);
  assert!(!one.is_null());

  assert_eq!(
    format!("{}", Hash256::ZERO),
    "0000000000000000000000000000000000000000000000000000000000000000"
  );
  assert_eq!(
    format!("{one}"),
    "0000000000000000000000000000000000000000000000000000000000000001"
  );
  assert_eq!(
    format!("{}", Hash256::from_bytes([0xff; 32])),
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  );
}

#[rstest]
fn ordering_is_lexicographic() {
  let zero = Hash256::ZERO;
  let one = Hash256::from_bytes(ONE_ARRAY);
  let max = Hash256::from_bytes([0xff; 32]);

  assert!(one > zero);
  assert!(max > one);
  assert!(max > zero);
}

#[rstest]
fn from_hex_with_prefix() {
  assert_eq!(Hash256::from_hex("0x01").unwrap().to_bytes(), ONE_ARRAY);
}

#[rstest]
fn from_hex_short() {
  assert_eq!(Hash256::from_hex("01").unwrap().to_bytes(), ONE_ARRAY);
}

#[rstest]
fn hex_errors() {
  assert_eq!(Hash256::from_hex("abc"), Err(ParseHexError::OddLength));
  assert!(matches!(Hash256::from_hex("zz"), Err(ParseHexError::InvalidChar(_))));
  let long = "ff".repeat(33);
  assert!(matches!(
    Hash256::from_hex(&long),
    Err(ParseHexError::InvalidLength { .. })
  ));
}

#[rstest]
fn hash160_roundtrip() {
  let bytes = hex!("0102030405060708090a0b0c0d0e0f1011121314");
  let h = Hash160::from_bytes(bytes);
  let hex = format!("{h}");
  assert_eq!(hex, "14131211100f0e0d0c0b0a090807060504030201");
  assert_eq!(Hash160::from_str(&hex).unwrap(), h);
}

#[rstest]
fn hash160_zero_and_null() {
  assert!(Hash160::ZERO.is_null());
  assert_eq!(Hash160::LEN, 20);
  let h = Hash160::from_bytes([0xff; 20]);
  assert!(!h.is_null());
}

#[rstest]
fn hash160_new_reverses() {
  let be = hex!("0102030405060708090a0b0c0d0e0f1011121314");
  let h = Hash160::new(be);
  // new() reverses, so first byte in LE is last byte of BE input
  assert_eq!(h.to_bytes()[0], 0x14);
  assert_eq!(h.to_bytes()[19], 0x01);
}
