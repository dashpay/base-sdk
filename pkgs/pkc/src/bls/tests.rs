//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test fixtures and constants.

use crate::bls_chia::SecretKey as ChiaSk;
use crate::bls_ietf::SecretKey as IetfSk;
use crate::prelude::*;

use hex_conservative::hex;
use rstest::*;

/// IKM producing the first deterministic test key.
pub const SEED_0: [u8; 32] = [0u8; 32];

/// IKM producing the second deterministic test key.
pub const SEED_1: [u8; 32] = [1u8; 32];

/// BLS12-381 scalar field order r, big-endian.
pub const GROUP_ORDER: [u8; 32] = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// Fixed 32-byte IKMs for deterministic test keys (all 0x00, 0x01, 0x02, 0x03).
pub const RSEED: [[u8; 32]; 4] = [[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]];

/// Test message.
pub const MSG_DEADBEEF: [u8; 32] = hex!("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe");

/// Parse a 32-byte hash from a hex string.
pub fn hash_from_hex(s: &str) -> dash_num::Hash256 {
  dash_num::Hash256::from_hex(s).unwrap()
}

/// Build a participant id whose low bytes encode `i`.
pub fn make_id(i: u32) -> dash_num::Hash256 {
  let mut bytes = [0u8; 32];
  bytes[28..32].copy_from_slice(&i.to_be_bytes());
  dash_num::Hash256::from_bytes(bytes)
}

/// Build `n` sequential participant ids `1..=n`.
pub fn sequential_ids(n: usize) -> Vec<dash_num::Hash256> {
  (1..=n).map(|i| make_id(i as u32)).collect()
}

/// Shared 32-byte test message fixture.
#[fixture]
pub fn msg32() -> [u8; 32] {
  MSG_DEADBEEF
}

/// Key derived from all-zero IKM.
#[fixture]
pub fn chia_sk0() -> ChiaSk {
  ChiaSk::generate(&RSEED[0]).unwrap()
}

/// Key derived from all-zero IKM.
#[fixture]
pub fn ietf_sk0() -> IetfSk {
  IetfSk::generate(&RSEED[0]).unwrap()
}

/// Key derived from all-one IKM.
#[fixture]
pub fn chia_sk1() -> ChiaSk {
  ChiaSk::generate(&RSEED[1]).unwrap()
}

/// Key derived from all-one IKM.
#[fixture]
pub fn ietf_sk1() -> IetfSk {
  IetfSk::generate(&RSEED[1]).unwrap()
}

/// Build a distinct 32-byte IKM from an index, for multi-signer tests.
pub fn test_ikm(i: u8) -> [u8; 32] {
  let mut ikm = [0u8; 32];
  ikm[0] = i;
  ikm[31] = i.wrapping_add(1);
  ikm
}

/// Build a distinct 32-byte message from an index, for multi-signer tests.
pub fn test_msg(i: u8) -> [u8; 32] {
  let mut m = [0u8; 32];
  m[0] = i.wrapping_mul(7);
  m[15] = i;
  m
}
