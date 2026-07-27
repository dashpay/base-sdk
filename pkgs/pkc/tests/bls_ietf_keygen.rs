//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Key generation and public key serialization tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use crate::common::bls::*;

#[cfg(feature = "serde")]
use dash_dev::assert_json_rt;
use dash_pkc::bls_ietf::SecretKey;
use rstest::*;

/// Secret key serialization round-trips.
#[rstest]
fn sk_roundtrip(ietf_sk0: SecretKey) {
  let bytes = ietf_sk0.to_bytes();
  let restored = SecretKey::from_bytes(&bytes).unwrap();
  assert_eq!(restored.public_key().to_bytes(), ietf_sk0.public_key().to_bytes());
}

/// IKM shorter than 32 bytes is rejected.
#[rstest]
fn sk_generate_rejects_short_ikm() {
  assert!(SecretKey::generate(&[0u8; 31]).is_err());
}

/// Compressed public key round-trips (48 bytes).
#[rstest]
fn pk_roundtrip(ietf_sk0: SecretKey) {
  let pk = ietf_sk0.public_key();
  let bytes = pk.to_bytes();
  assert_eq!(bytes.len(), 48);
  let restored = dash_pkc::bls_ietf::PublicKey::from_bytes(&bytes).unwrap();
  assert_eq!(restored, pk);
}

/// Serde round-trip for PublicKey.
#[cfg(feature = "serde")]
#[rstest]
fn serde_pk_roundtrip(ietf_sk0: SecretKey) {
  let pk = ietf_sk0.public_key();
  assert_json_rt(&pk);
}

/// Same key serialized under IETF and legacy formats must differ.
#[rstest]
fn cross_format_pk_differs(ietf_sk0: SecretKey) {
  let ietf_bytes = ietf_sk0.public_key().to_bytes();
  let legacy_sk = dash_pkc::bls_chia::SecretKey::from_bytes(&ietf_sk0.to_bytes()).unwrap();
  let legacy_bytes = legacy_sk.public_key().to_bytes();
  assert_ne!(ietf_bytes, legacy_bytes, "same point must serialize differently");
}

mod kat {
  use dash_dev::{vec_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct KeygenVector {
    sk: String,
    pk: String,
  }

  #[test]
  fn kat_derive_pk() {
    let vecs: Vec<KeygenVector> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ietf_keygen").vectors("derive_pk");

    for v in &vecs {
      let sk_bytes: [u8; 32] = vec_from_hex(&v.sk).try_into().unwrap();
      let sk = dash_pkc::bls_ietf::SecretKey::from_bytes(&sk_bytes).unwrap();
      assert_eq!(
        sk.public_key().to_bytes().to_lower_hex_string(),
        v.pk,
        "pk mismatch for sk {}",
        v.sk
      );
    }
  }
}
