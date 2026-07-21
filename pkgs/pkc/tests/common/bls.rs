//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared BLS test constants.

use dash_pkc::{bls_chia::SecretKey as ChiaSk, bls_ietf::SecretKey as IetfSk};
use hex_literal::hex;
use rstest::*;

/// BLS12-381 scalar field order r, big-endian.
pub const GROUP_ORDER: [u8; 32] = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// Fixed 32-byte IKMs for deterministic test keys (all 0x00, 0x01, 0x02, 0x03).
pub const RSEED: [[u8; 32]; 4] = [[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]];

/// Shared 32-byte test message.
#[fixture]
pub fn msg32() -> [u8; 32] {
  crate::common::MSG_DEADBEEF
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
