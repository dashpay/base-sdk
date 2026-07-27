//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signing and verification tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use crate::common::bls::*;

use dash_pkc::bls_ietf::{SecretKey, Signature};
use hex_literal::hex;
use rstest::*;

/// PyECC reference vector: known sk -> known sig bytes.
#[rstest]
fn pyecc_sign_verify() {
  let sk = SecretKey::from_bytes(&hex!(
    "0101010101010101010101010101010101"
    "010101010101010101010101010101"
  ))
  .unwrap();
  let msg = hex!("030104010509");
  let sig = sk.sign(&msg);

  let expected_sig = hex!(
    "96ba34fac33c7f129d602a0bc8a3d43f"
    "9abc014eceaab7359146b4b150e57b80"
    "8645738f35671e9e10e0d862a30cab70"
    "074eb5831d13e6a5b162d01eebe687d0"
    "164adbd0a864370a7c222a2768d7704d"
    "a254f1bf1823665bc2361f9dd8c00e99"
  );
  assert_eq!(sig.to_bytes(), expected_sig);

  let pk = sk.public_key();
  assert!(sig.verify(&msg, &pk).is_ok());
}

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
  let json = serde_json::to_string(&sig).unwrap();
  let restored: Signature = serde_json::from_str(&json).unwrap();
  assert_eq!(restored, sig);
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

mod kat {
  use super::common::{self, VectorFile};

  use dash_dev::vec_from_hex;
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    msg: String,
    sig: String,
  }

  #[test]
  fn kat_sign() {
    let f: VectorFile = common::load("bls_ietf_sign");
    let vecs: Vec<SignVector> = common::parse_sub(&f, "sign");

    for v in &vecs {
      let sk_bytes: [u8; 32] = vec_from_hex(&v.sk).try_into().unwrap();
      let msg = vec_from_hex(&v.msg);
      let sk = dash_pkc::bls_ietf::SecretKey::from_bytes(&sk_bytes).unwrap();
      let sig = sk.sign(&msg);
      assert_eq!(
        sig.to_bytes().to_lower_hex_string(),
        v.sig,
        "sig mismatch for sk={} msg={}",
        v.sk,
        v.msg
      );
    }
  }
}
