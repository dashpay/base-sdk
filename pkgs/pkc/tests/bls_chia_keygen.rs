//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Key generation and public key serialization tests for
//! bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use dash_pkc::bls_chia::SecretKey;
use rstest::*;

/// Key derived from all-zero IKM.
#[fixture]
fn sk_seed0() -> SecretKey {
  SecretKey::generate(&common::SEED_0).unwrap()
}

/// Secret key serialization round-trips.
#[rstest]
fn sk_roundtrip(sk_seed0: SecretKey) {
  let bytes = sk_seed0.to_bytes();
  let restored = SecretKey::from_bytes(&bytes).unwrap();
  assert_eq!(restored.public_key().to_bytes(), sk_seed0.public_key().to_bytes());
}

/// IKM shorter than 32 bytes is rejected.
#[rstest]
fn sk_generate_rejects_short_ikm() {
  assert!(SecretKey::generate(&[0u8; 31]).is_err());
}

/// Legacy public key round-trips (48 bytes).
#[rstest]
fn pk_roundtrip(sk_seed0: SecretKey) {
  let pk = sk_seed0.public_key();
  let bytes = pk.to_bytes();
  assert_eq!(bytes.len(), 48);
  let restored = dash_pkc::bls_chia::PublicKey::from_bytes(&bytes).unwrap();
  assert_eq!(restored, pk);
}

/// Serde round-trip for PublicKey.
#[cfg(feature = "serde")]
#[rstest]
fn serde_pk_roundtrip(sk_seed0: SecretKey) {
  let pk = sk_seed0.public_key();
  let json = serde_json::to_string(&pk).unwrap();
  let restored: dash_pkc::bls_chia::PublicKey = serde_json::from_str(&json).unwrap();
  assert_eq!(restored, pk);
}

/// Same key serialized under legacy and IETF formats must produce
/// different bytes.
#[rstest]
fn cross_format_pk_differs(sk_seed0: SecretKey) {
  let legacy_bytes = sk_seed0.public_key().to_bytes();
  let ietf_sk = dash_pkc::bls_ietf::SecretKey::from_bytes(&sk_seed0.to_bytes()).unwrap();
  let ietf_bytes = ietf_sk.public_key().to_bytes();
  assert_ne!(legacy_bytes, ietf_bytes, "same point must serialize differently");
}

mod kat {
  use super::common::{self, decode_hex, VectorFile};

  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct KeygenVector {
    sk: String,
    pk: String,
  }

  #[test]
  fn kat_derive_pk() {
    let f: VectorFile = common::load("bls_chia_keygen");
    let vecs: Vec<KeygenVector> = common::parse_sub(&f, "derive_pk");

    for v in &vecs {
      let sk_bytes: [u8; 32] = decode_hex(&v.sk).try_into().unwrap();
      let sk = dash_pkc::bls_chia::SecretKey::from_bytes(&sk_bytes).unwrap();
      assert_eq!(
        sk.public_key().to_bytes().to_lower_hex_string(),
        v.pk,
        "pk mismatch for sk {}",
        v.sk
      );
    }
  }
}
