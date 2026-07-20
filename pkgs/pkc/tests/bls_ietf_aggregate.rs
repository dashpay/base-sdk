//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and secure verification tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use dash_pkc::bls_ietf::{
  aggregate_pk, aggregate_sig, fast_verify_aggregates, verify_aggregates, SecretKey, Signature,
};
use hex_literal::hex;
use rstest::*;

/// Key derived from all-zero IKM.
#[fixture]
fn sk_seed0() -> SecretKey {
  SecretKey::generate(&common::SEED_0).unwrap()
}

/// Key derived from all-one IKM.
#[fixture]
fn sk_seed1() -> SecretKey {
  SecretKey::generate(&common::SEED_1).unwrap()
}

/// Aggregated public key serializes to 48 bytes.
#[rstest]
fn aggregate_pk_roundtrip(sk_seed0: SecretKey, sk_seed1: SecretKey) {
  let pk1 = sk_seed0.public_key();
  let pk2 = sk_seed1.public_key();
  let agg = aggregate_pk(&[&pk1, &pk2]).unwrap();
  assert_eq!(agg.to_bytes().len(), 48);
}

/// Empty aggregation is rejected.
#[rstest]
fn aggregate_empty_fails() {
  let empty_pk: Vec<&dash_pkc::bls_ietf::PublicKey> = vec![];
  assert!(aggregate_pk(&empty_pk).is_err());
  let empty_sig: Vec<&Signature> = vec![];
  assert!(aggregate_sig(&empty_sig).is_err());
}

/// Aggregate verify over two distinct messages.
#[rstest]
fn aggregate_two_distinct_messages() {
  let sk1 = SecretKey::generate(&common::SEED_0).unwrap();
  let sk2 = SecretKey::generate(&common::SEED_1).unwrap();

  let msg1 = hex!("070809");
  let msg2 = hex!("0a0b0c");
  let sig1 = sk1.sign(&msg1);
  let sig2 = sk2.sign(&msg2);
  let agg = aggregate_sig(&[&sig1, &sig2]).unwrap();

  let pk1 = sk1.public_key();
  let pk2 = sk2.public_key();
  let msgs: Vec<&[u8]> = vec![msg1.as_slice(), msg2.as_slice()];
  assert!(verify_aggregates(&agg, &msgs, &[&pk1, &pk2]).is_ok());
}

/// Fast aggregate verify with a shared message.
#[rstest]
fn fast_verify_same_message(sk_seed0: SecretKey, sk_seed1: SecretKey) {
  let msg = b"same message for both signers";
  let sig1 = sk_seed0.sign(msg);
  let sig2 = sk_seed1.sign(msg);
  let agg = aggregate_sig(&[&sig1, &sig2]).unwrap();
  let pk1 = sk_seed0.public_key();
  let pk2 = sk_seed1.public_key();
  assert!(fast_verify_aggregates(&agg, msg, &[&pk1, &pk2]).is_ok());
}

/// Fast aggregate verify is order-independent.
#[rstest]
fn fast_verify_order_independent() {
  let sk1 = SecretKey::generate(&common::SEED_1).unwrap();
  let sk2 = SecretKey::generate(&[2u8; 32]).unwrap();
  let sk3 = SecretKey::generate(&[3u8; 32]).unwrap();
  let msg = b"order test";
  let pk1 = sk1.public_key();
  let pk2 = sk2.public_key();
  let pk3 = sk3.public_key();
  let sig1 = sk1.sign(msg);
  let sig2 = sk2.sign(msg);
  let sig3 = sk3.sign(msg);
  let agg = aggregate_sig(&[&sig1, &sig2, &sig3]).unwrap();

  // Both orderings of pks verify the same aggregate.
  assert!(fast_verify_aggregates(&agg, msg, &[&pk1, &pk2, &pk3]).is_ok());
  assert!(fast_verify_aggregates(&agg, msg, &[&pk3, &pk1, &pk2]).is_ok());
}

/// Secure verify rejects naively aggregated signatures.
#[rstest]
fn secure_verify_rejects_naive_aggregate(sk_seed0: SecretKey, sk_seed1: SecretKey) {
  use dash_pkc::bls_ietf::secure_verify_aggregates;

  let msg = b"secure test";
  let sig1 = sk_seed0.sign(msg);
  let sig2 = sk_seed1.sign(msg);
  let agg = aggregate_sig(&[&sig1, &sig2]).unwrap();
  let pk1 = sk_seed0.public_key();
  let pk2 = sk_seed1.public_key();

  // Fast (non-secure) verify should succeed.
  assert!(fast_verify_aggregates(&agg, msg, &[&pk1, &pk2]).is_ok());
  // Secure verify uses different weighting, so naively
  // aggregated sigs should fail.
  assert!(secure_verify_aggregates(&agg, msg, &[&pk1, &pk2]).is_err());
}

mod kat {
  use super::common::{self, decode_hex, VectorFile};

  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct AggregatePkVector {
    pks: Vec<String>,
    agg_pk: String,
  }

  #[derive(Deserialize)]
  struct AggregateSigVector {
    sigs: Vec<String>,
    agg_sig: String,
  }

  #[derive(Deserialize)]
  struct AggregateSkVector {
    sks: Vec<String>,
    agg_sk: String,
  }

  #[derive(Deserialize)]
  #[expect(dead_code, reason = "deserialized from corpus JSON")]
  struct SecureAggVector {
    msg: String,
    pks: Vec<String>,
    sigs: Vec<String>,
    agg_sig_secure: String,
  }

  #[test]
  fn kat_aggregate_pk() {
    let f: VectorFile = common::load("bls_ietf_aggregate");
    let vecs: Vec<AggregatePkVector> = common::parse_sub(&f, "aggregate_pk");

    for v in &vecs {
      let pks: Vec<dash_pkc::bls_ietf::PublicKey> = v
        .pks
        .iter()
        .map(|h| {
          let b: [u8; 48] = decode_hex(h).try_into().unwrap();
          dash_pkc::bls_ietf::PublicKey::from_bytes(&b).unwrap()
        })
        .collect();
      let pk_refs: Vec<_> = pks.iter().collect();
      let agg = dash_pkc::bls_ietf::aggregate_pk(&pk_refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_pk);
    }
  }

  #[test]
  fn kat_aggregate_sig() {
    let f: VectorFile = common::load("bls_ietf_aggregate");
    let vecs: Vec<AggregateSigVector> = common::parse_sub(&f, "aggregate_sig");

    for v in &vecs {
      let sigs: Vec<dash_pkc::bls_ietf::Signature> = v
        .sigs
        .iter()
        .map(|h| {
          let b: [u8; 96] = decode_hex(h).try_into().unwrap();
          dash_pkc::bls_ietf::Signature::from_bytes(&b).unwrap()
        })
        .collect();
      let sig_refs: Vec<_> = sigs.iter().collect();
      let agg = dash_pkc::bls_ietf::aggregate_sig(&sig_refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig);
    }
  }

  #[test]
  fn kat_aggregate_sk() {
    let f: VectorFile = common::load("bls_aggregate");
    let vecs: Vec<AggregateSkVector> = common::parse_sub(&f, "aggregate_sk");

    for v in &vecs {
      let sks: Vec<dash_pkc::bls_ietf::SecretKey> = v
        .sks
        .iter()
        .map(|h| {
          let b: [u8; 32] = decode_hex(h).try_into().unwrap();
          dash_pkc::bls_ietf::SecretKey::from_bytes(&b).unwrap()
        })
        .collect();
      let sk_refs: Vec<_> = sks.iter().collect();
      let agg = dash_pkc::bls_ietf::aggregate_sk(&sk_refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sk);
    }
  }

  #[test]
  fn kat_secure_verify_aggregates() {
    let f: VectorFile = common::load("bls_ietf_secure_aggregate");
    let vecs: Vec<SecureAggVector> = common::parse_sub(&f, "secure_verify_aggregates");

    for v in &vecs {
      let msg = decode_hex(&v.msg);
      let pks: Vec<dash_pkc::bls_ietf::PublicKey> = v
        .pks
        .iter()
        .map(|h| {
          let b: [u8; 48] = decode_hex(h).try_into().unwrap();
          dash_pkc::bls_ietf::PublicKey::from_bytes(&b).unwrap()
        })
        .collect();

      let expected_agg: [u8; 96] = decode_hex(&v.agg_sig_secure).try_into().unwrap();
      let agg_sig = dash_pkc::bls_ietf::Signature::from_bytes(&expected_agg).unwrap();
      let pk_refs: Vec<_> = pks.iter().collect();

      // The securely aggregated signature must pass
      // secure_verify_aggregates.
      assert!(
        dash_pkc::bls_ietf::secure_verify_aggregates(&agg_sig, &msg, &pk_refs).is_ok(),
        "secure verify failed for n={}",
        v.pks.len()
      );
    }
  }
}
