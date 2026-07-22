//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signing and verification tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

use common::*;
#[cfg(feature = "serde")]
use dash_dev::assert_json_rt;
use dash_pkc::{bls::tests as common, bls_chia::SecretKey, bls_chia::Signature};
use rstest::*;

/// Sign then verify round-trips.
#[rstest]
fn sign_verify_roundtrip(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let sig = chia_sk0.sign(&msg32);
  let pk = chia_sk0.public_key();
  assert!(sig.verify(&msg32, &pk).is_ok());
}

/// Verification rejects a tampered message.
#[rstest]
fn verify_rejects_wrong_message(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let sig = chia_sk0.sign(&msg32);
  let mut bad = msg32;
  bad[0] ^= 0xff;
  assert!(sig.verify(&bad, &chia_sk0.public_key()).is_err());
}

/// Verification rejects a different signer's key.
#[rstest]
fn verify_rejects_wrong_key(chia_sk0: SecretKey, chia_sk1: SecretKey, msg32: [u8; 32]) {
  let sig = chia_sk0.sign(&msg32);
  assert!(sig.verify(&msg32, &chia_sk1.public_key()).is_err());
}

/// Legacy BLS signing is deterministic.
#[rstest]
fn sign_is_deterministic(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let sig1 = chia_sk0.sign(&msg32);
  let sig2 = chia_sk0.sign(&msg32);
  assert_eq!(sig1, sig2);
}

/// Legacy signature round-trips (96 bytes).
#[rstest]
fn sig_roundtrip(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let sig = chia_sk0.sign(&msg32);
  let bytes = sig.to_bytes();
  assert_eq!(bytes.len(), 96);
  let restored = Signature::from_bytes(&bytes).unwrap();
  assert_eq!(restored, sig);
}

/// Serde round-trip for Signature.
#[cfg(feature = "serde")]
#[rstest]
fn serde_sig_roundtrip(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let sig = chia_sk0.sign(&msg32);
  assert_json_rt(&sig);
}

/// Same signature serialized under legacy and IETF formats
/// must produce different bytes.
#[rstest]
fn cross_format_sig_differs(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let legacy_sig = chia_sk0.sign(&msg32).to_bytes();
  let ietf_sk = dash_pkc::bls_ietf::SecretKey::from_bytes(&chia_sk0.to_bytes()).unwrap();
  let ietf_sig = ietf_sk.sign(&msg32).to_bytes();
  assert_ne!(legacy_sig, ietf_sig, "same point must serialize differently");
}

/// Same key material produces different signatures under legacy
/// and IETF schemes (different hash-to-G2).
#[rstest]
fn legacy_sig_differs_from_ietf() {
  let ikm = [0u8; 32];
  let legacy_sk = dash_pkc::bls_chia::SecretKey::generate(&ikm).unwrap();
  let ietf_sk = dash_pkc::bls_ietf::SecretKey::generate(&ikm).unwrap();
  assert_eq!(legacy_sk.to_bytes(), ietf_sk.to_bytes());

  let msg = [0x42u8; 32];
  let legacy_sig = legacy_sk.sign(&msg);
  let ietf_sig = ietf_sk.sign(&msg);
  assert_ne!(legacy_sig.to_bytes(), ietf_sig.to_bytes());
}

/// Same curve point, different wire format.
#[rstest]
fn legacy_pk_serialization_differs_from_ietf() {
  let ikm = [0u8; 32];
  let legacy_pk = dash_pkc::bls_chia::SecretKey::generate(&ikm).unwrap().public_key();
  let ietf_pk = dash_pkc::bls_ietf::SecretKey::generate(&ikm).unwrap().public_key();
  assert_ne!(legacy_pk.to_bytes(), ietf_pk.to_bytes());
}

/// Reference vectors through the public wrapper.
///
/// The scheme-level KAT in `bls::scheme_chia` pins `BlsScChia::sign`; this
/// pins that `SecretKey::sign` is still wired to it.
mod kat {
  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    msg: String,
    sig: String,
  }

  #[test]
  fn public_api_signing_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_sign");
    for v in corpus.vectors::<SignVector>("sign") {
      let sk = dash_pkc::bls_chia::SecretKey::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      assert_eq!(sk.sign(&msg).to_bytes().to_lower_hex_string(), v.sig);
    }
  }
}
