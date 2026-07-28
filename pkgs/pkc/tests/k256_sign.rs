//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signing, verification, and recovery tests for k256.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

#[cfg(feature = "serde")]
use dash_dev::assert_json_rt;
use dash_pkc::k256::{PublicKey, RecoveryId, SecretKey, Signature};
use hex_literal::hex;
use rstest::*;

/// Shared test keypair.
#[fixture]
fn alice() -> SecretKey {
  SecretKey::from_bytes(&hex!(
    "0123456789abcdef0123456789abcdef"
    "fedcba9876543210fedcba9876543210"
  ))
  .unwrap()
}

/// Shared test message digest.
#[fixture]
fn msg_hash() -> [u8; 32] {
  common::MSG_DEADBEEF
}

/// Sign then verify with the same key succeeds.
#[rstest]
fn sign_verify_roundtrip(alice: SecretKey, msg_hash: [u8; 32]) {
  let sig = alice.sign(&msg_hash).unwrap();
  let pk = alice.public_key();
  assert!(pk.verify(&msg_hash, &sig).is_ok());
}

/// Verification rejects a tampered message.
#[rstest]
fn verify_rejects_wrong_message(alice: SecretKey, msg_hash: [u8; 32]) {
  let sig = alice.sign(&msg_hash).unwrap();
  let pk = alice.public_key();
  let mut bad_hash = msg_hash;
  bad_hash[0] ^= 0xff;
  assert!(pk.verify(&bad_hash, &sig).is_err());
}

/// Verification rejects a different signer's key.
#[rstest]
fn verify_rejects_wrong_key(alice: SecretKey, msg_hash: [u8; 32]) {
  let sig = alice.sign(&msg_hash).unwrap();
  let bob = SecretKey::from_bytes(&hex!(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ))
  .unwrap();
  assert!(bob.public_key().verify(&msg_hash, &sig).is_err());
}

/// Compact signature round-trips.
#[rstest]
fn signature_compact_roundtrip(alice: SecretKey, msg_hash: [u8; 32]) {
  let sig = alice.sign(&msg_hash).unwrap();
  let bytes = sig.to_compact();
  let restored = Signature::from_compact(&bytes).unwrap();
  assert_eq!(restored, sig);
}

/// Recoverable signature yields the original public key.
#[rstest]
fn sign_recoverable_roundtrip(alice: SecretKey, msg_hash: [u8; 32]) {
  let (sig, rid) = alice.sign_recoverable(&msg_hash).unwrap();
  let recovered = PublicKey::recover(&msg_hash, &sig, rid).unwrap();
  assert_eq!(recovered, alice.public_key());
}

/// Out-of-range recovery ids are rejected.
#[rstest]
fn recovery_id_rejects_out_of_range() {
  assert!(RecoveryId::new(4).is_err());
  assert!(RecoveryId::new(255).is_err());
}

/// Valid recovery ids round-trip.
#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
fn recovery_id_roundtrip(#[case] id: u8) {
  let rid = RecoveryId::new(id).unwrap();
  assert_eq!(rid.to_byte(), id);
}

/// RFC 6979 signing is deterministic.
#[rstest]
fn sign_is_deterministic(alice: SecretKey, msg_hash: [u8; 32]) {
  let sig1 = alice.sign(&msg_hash).unwrap();
  let sig2 = alice.sign(&msg_hash).unwrap();
  assert_eq!(sig1, sig2);
}

/// Serde round-trip for Signature.
#[cfg(feature = "serde")]
#[rstest]
fn serde_sig_roundtrip(alice: SecretKey, msg_hash: [u8; 32]) {
  let sig = alice.sign(&msg_hash).unwrap();
  assert_json_rt(&sig);
}

/// Serde round-trip for RecoveryId.
#[cfg(feature = "serde")]
#[rstest]
fn serde_recovery_id_roundtrip() {
  let rid = RecoveryId::new(1).unwrap();
  assert_json_rt(&rid);
}

mod kat {
  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    msg: String,
    sig: String,
    recovery_id: u8,
  }

  #[derive(Deserialize)]
  struct RecoverVector {
    msg: String,
    sig: String,
    recovery_id: u8,
    pk: String,
  }

  #[test]
  fn kat_sign_recoverable() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "k256_sign");
    let vecs: Vec<SignVector> = corpus.vectors("sign_recoverable");

    for v in &vecs {
      let sk_bytes: [u8; 32] = arr_from_hex(&v.sk);
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      let sk = dash_pkc::k256::SecretKey::from_bytes(&sk_bytes).unwrap();
      let (sig, rid) = sk.sign_recoverable(&msg).unwrap();
      assert_eq!(
        sig.to_compact().to_lower_hex_string(),
        v.sig,
        "sig mismatch for sk={} msg={}",
        v.sk,
        v.msg
      );
      assert_eq!(rid.to_byte(), v.recovery_id, "recovery_id mismatch");
    }
  }

  #[test]
  fn kat_recover() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "k256_sign");
    let vecs: Vec<RecoverVector> = corpus.vectors("recover");

    for v in &vecs {
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      let sig_bytes: [u8; 64] = arr_from_hex(&v.sig);
      let sig = dash_pkc::k256::Signature::from_compact(&sig_bytes).unwrap();
      let rid = dash_pkc::k256::RecoveryId::new(v.recovery_id).unwrap();
      let pk = dash_pkc::k256::PublicKey::recover(&msg, &sig, rid).unwrap();
      assert_eq!(pk.to_bytes().to_lower_hex_string(), v.pk, "recovered pk mismatch");
    }
  }
}
