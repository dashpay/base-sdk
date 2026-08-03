//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common test definitions.

use crate::ecdsa::{EcdsaPublicKey, EcdsaRecoveryId, EcdsaSecretKey, EcdsaSignature};

use hex_conservative::hex;
use rstest::fixture;

pub const ALICE_SK: [u8; 32] = hex!("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");
pub const BOB_SK: [u8; 32] = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
pub const MSG: [u8; 32] = hex!("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe");

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
pub fn alice_rec_sig() -> (EcdsaSignature, EcdsaRecoveryId) {
  alice_sk().sign_recoverable(&MSG).unwrap()
}

#[fixture]
pub fn alice_sig() -> EcdsaSignature {
  alice_sk().sign(&MSG).unwrap()
}
