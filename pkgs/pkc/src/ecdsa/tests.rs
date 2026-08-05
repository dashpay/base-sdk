//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common test definitions.

use crate::ecdsa::{EcdsaPublicKey, EcdsaRecSignature, EcdsaSecretKey, EcdsaSignature};

use hex_conservative::hex;
use rstest::fixture;

pub const ALICE_SK: [u8; 32] = hex!("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");
pub const BOB_SK: [u8; 32] = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
pub const MSG: [u8; 32] = hex!("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe");

/// secp256k1 group order, big-endian.
pub(crate) const ORDER: [u8; 32] = hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// Negate a scalar modulo the curve order (`order - s`), used to turn a low-S
/// signature into a high-S one for tests as the library itself only ever
/// produces low-S signatures.
pub(crate) fn negate_scalar(s: &[u8]) -> [u8; 32] {
  let mut out = [0u8; 32];
  let mut borrow = 0i16;
  for i in (0..32).rev() {
    let diff = i16::from(ORDER[i]) - i16::from(s[i]) - borrow;
    borrow = i16::from(diff < 0);
    out[i] = diff.rem_euclid(256) as u8;
  }
  out
}

/// Derive a distinct 32-byte message digest from an index.
pub fn message_hash(i: u16) -> [u8; 32] {
  let mut h = [0u8; 32];
  h[0] = i as u8;
  h[31] = (i >> 8) as u8;
  h
}

#[fixture]
pub fn alice_pk() -> EcdsaPublicKey {
  alice_sk().public_key()
}

#[fixture]
pub fn alice_sk() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&ALICE_SK).unwrap()
}

#[fixture]
pub fn bob_sk() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&BOB_SK).unwrap()
}

#[fixture]
pub fn alice_rec_sig() -> EcdsaRecSignature {
  alice_sk().sign_recoverable(&MSG, true).unwrap()
}

#[fixture]
pub fn alice_sig() -> EcdsaSignature {
  alice_sk().sign(&MSG).unwrap()
}
