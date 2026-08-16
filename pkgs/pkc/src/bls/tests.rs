//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test fixtures and constants.

use crate::prelude::*;

use hex_conservative::hex;

/// BLS12-381 scalar field order r, big-endian.
pub const GROUP_ORDER: [u8; 32] = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// Fixed 32-byte IKMs for deterministic test keys (all 0x00, 0x01, 0x02, 0x03).
pub const RSEED: [[u8; 32]; 4] = [[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]];

/// Test message.
pub const MSG_DEADBEEF: [u8; 32] = hex!("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe");

/// A message distinct from [`MSG_DEADBEEF`].
pub const MSG_8BADFOOD: [u8; 32] = hex!("8badf00d8badf00d8badf00d8badf00dfeedfacefeedfacefeedfacefeedface");

/// Smallest off-subgroup G1 point, Chia-encoded: `x = 4` is the least `x`
/// with `x^3 + 4` a residue mod `p` and `[r]P != O`.
pub const G1_OFF_SUBGROUP_CHIA: [u8; 48] =
  hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004");

/// [`G1_OFF_SUBGROUP_CHIA`] in the IETF encoding: compression bit set, sign
/// bit clear.
pub const G1_OFF_SUBGROUP_IETF: [u8; 48] =
  hex!("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004");

/// [`G1_OFF_SUBGROUP_CHIA`] with the field prime added to `x`, so the
/// coordinate is out of range while the flag bits stay untouched.
pub const G1_X_GE_PRIME_CHIA: [u8; 48] =
  hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaf");

/// The least out-of-range `x`, the field prime itself, Chia-encoded.
pub const G1_X_EQ_PRIME_CHIA: [u8; 48] =
  hex!("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

/// The largest `x` the Chia encoding can carry, every bit below the three
/// flags set, so nothing beyond the flags is left to reinterpret.
pub const G1_X_MAX_CHIA: [u8; 48] =
  hex!("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/// Smallest off-subgroup G2 point, Chia-encoded: `x.c0 = 2` is the least
/// value with `x^3 + 4(1 + u)` square in `Fp2` and `[r]P != O`.
pub const G2_OFF_SUBGROUP_CHIA: [u8; 96] = hex!(concat!(
  "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
));

/// [`G2_OFF_SUBGROUP_CHIA`] in the IETF encoding: `[x.c1, x.c0]` order,
/// compression bit and sign bit set.
pub const G2_OFF_SUBGROUP_IETF: [u8; 96] = hex!(concat!(
  "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"
));

/// Re-encode a Chia G1 coordinate under the IETF compression bit.
pub const fn ietf_g1_encoding(mut chia: [u8; 48]) -> [u8; 48] {
  chia[0] |= 0x80;
  chia
}

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

/// Build a distinct 32-byte IKM from an index, for multi-signer tests.
///
/// The index is carried in full, so a run of more than 256 signers gets that
/// many distinct keys instead of wrapping at 256.
pub fn test_ikm(i: usize) -> [u8; 32] {
  let mut ikm = [0u8; 32];
  ikm[..8].copy_from_slice(&(i as u64).to_be_bytes());
  ikm[24..].copy_from_slice(&(i as u64).wrapping_add(1).to_be_bytes());
  ikm
}

/// Build a distinct 32-byte message from an index, for multi-signer tests.
///
/// As with [`test_ikm`], the index is carried in full to keep messages
/// distinct past 256.
pub fn test_msg(i: usize) -> [u8; 32] {
  let mut m = [0u8; 32];
  m[..8].copy_from_slice(&(i as u64).to_be_bytes());
  m[8..16].copy_from_slice(&(i as u64).wrapping_mul(7).to_be_bytes());
  m
}

#[cfg(test)]
mod builders {
  use super::*;

  use rstest::rstest;

  #[rstest]
  #[case::ikm(test_ikm)]
  #[case::msg(test_msg)]
  fn injective_past_256(#[case] build: fn(usize) -> [u8; 32]) {
    let mut built: Vec<[u8; 32]> = (0..1000).map(build).collect();
    built.sort_unstable();
    let total = built.len();
    built.dedup();
    assert_eq!(built.len(), total, "index does not survive into the output");
  }
}
