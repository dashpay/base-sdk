//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signing and verification tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]

use common::*;
#[cfg(feature = "serde")]
use dash_dev::assert_json_rt;
use dash_pkc::{bls::tests as common, bls_ietf::SecretKey, bls_ietf::Signature};
use hex_literal::hex;
use rstest::*;

/// Sign then verify with a generated key succeeds and is
/// deterministic.
#[rstest]
fn sign_verify_known_key() {
  let sk = SecretKey::generate(&RSEED[0]).unwrap();
  let msg = hex!("070809");
  let sig = sk.sign(&msg);
  assert!(sig.verify(&msg, &sk.public_key()).is_ok());
  assert_eq!(sk.sign(&msg).to_bytes(), sig.to_bytes());
}

/// Sign then verify round-trips.
#[rstest]
fn sign_verify_roundtrip(ietf_sk0: SecretKey) {
  let msg = b"hello dash";
  let sig = ietf_sk0.sign(msg);
  assert!(sig.verify(msg, &ietf_sk0.public_key()).is_ok());
}

/// Verification rejects a tampered message.
#[rstest]
fn verify_rejects_wrong_message(ietf_sk0: SecretKey) {
  let sig = ietf_sk0.sign(b"right");
  assert!(sig.verify(b"wrong", &ietf_sk0.public_key()).is_err());
}

/// Verification rejects a different signer's key.
#[rstest]
fn verify_rejects_wrong_key(ietf_sk0: SecretKey, ietf_sk1: SecretKey) {
  let sig = ietf_sk0.sign(b"msg");
  assert!(sig.verify(b"msg", &ietf_sk1.public_key()).is_err());
}

/// Compressed signature round-trips (96 bytes).
#[rstest]
fn sig_roundtrip(ietf_sk0: SecretKey) {
  let sig = ietf_sk0.sign(b"test");
  let bytes = sig.to_bytes();
  assert_eq!(bytes.len(), 96);
  let restored = Signature::from_bytes(&bytes).unwrap();
  assert_eq!(restored, sig);
}

/// BLS signing is deterministic.
#[rstest]
fn sign_is_deterministic(ietf_sk0: SecretKey) {
  let msg = b"determinism check";
  let sig1 = ietf_sk0.sign(msg);
  let sig2 = ietf_sk0.sign(msg);
  assert_eq!(sig1, sig2);
}

/// Serde round-trip for Signature.
#[cfg(feature = "serde")]
#[rstest]
fn serde_sig_roundtrip(ietf_sk0: SecretKey) {
  let sig = ietf_sk0.sign(b"serde test");
  assert_json_rt(&sig);
}

/// Same signature under IETF and legacy formats must differ.
#[rstest]
fn cross_format_sig_differs(ietf_sk0: SecretKey) {
  // Sign the same 32-byte message on both paths; only the format differs.
  let msg = [0x42u8; 32];
  let ietf_sig = ietf_sk0.sign(&msg).to_bytes();
  let legacy_sk = dash_pkc::bls_chia::SecretKey::from_bytes(&ietf_sk0.to_bytes()).unwrap();
  let legacy_sig = legacy_sk.sign(&msg).to_bytes();
  assert_ne!(ietf_sig, legacy_sig, "same key must produce different sigs");
}

/// Reference vectors through the public wrapper.
///
/// The scheme-level KAT in `bls::scheme_ietf` pins `BlsScIetf::sign`; this
/// pins that `SecretKey::sign` is still wired to it, DST included.
mod kat {
  use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
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
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ietf_sign");
    for v in corpus.vectors::<SignVector>("sign") {
      let sk = dash_pkc::bls_ietf::SecretKey::from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let sig = sk.sign(&vec_from_hex(&v.msg));
      assert_eq!(sig.to_bytes().to_lower_hex_string(), v.sig);
    }
  }
}
