//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and secure verification tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]

use common::*;
use dash_pkc::bls::tests as common;
use dash_pkc::bls_ietf::{
  aggregate_pk, aggregate_sig, fast_verify_aggregates, verify_aggregates, PublicKey, SecretKey, Signature,
};
use hex_literal::hex;
use rstest::*;

/// Aggregated public key serializes to 48 bytes.
#[rstest]
fn aggregate_pk_roundtrip(ietf_sk0: SecretKey, ietf_sk1: SecretKey) {
  let pk1 = ietf_sk0.public_key();
  let pk2 = ietf_sk1.public_key();
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
  let sk1 = SecretKey::generate(&RSEED[0]).unwrap();
  let sk2 = SecretKey::generate(&RSEED[1]).unwrap();

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
fn fast_verify_same_message(ietf_sk0: SecretKey, ietf_sk1: SecretKey) {
  let msg = b"same message for both signers";
  let sig1 = ietf_sk0.sign(msg);
  let sig2 = ietf_sk1.sign(msg);
  let agg = aggregate_sig(&[&sig1, &sig2]).unwrap();
  let pk1 = ietf_sk0.public_key();
  let pk2 = ietf_sk1.public_key();
  assert!(fast_verify_aggregates(&agg, msg, &[&pk1, &pk2]).is_ok());
}

/// Fast aggregate verify is order-independent.
#[rstest]
fn fast_verify_order_independent() {
  let sk1 = SecretKey::generate(&RSEED[1]).unwrap();
  let sk2 = SecretKey::generate(&RSEED[2]).unwrap();
  let sk3 = SecretKey::generate(&RSEED[3]).unwrap();
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
fn secure_verify_rejects_naive_aggregate(ietf_sk0: SecretKey, ietf_sk1: SecretKey) {
  use dash_pkc::bls_ietf::secure_verify_aggregates;

  let msg = b"secure test";
  let sig1 = ietf_sk0.sign(msg);
  let sig2 = ietf_sk1.sign(msg);
  let agg = aggregate_sig(&[&sig1, &sig2]).unwrap();
  let pk1 = ietf_sk0.public_key();
  let pk2 = ietf_sk1.public_key();

  // Fast (non-secure) verify should succeed.
  assert!(fast_verify_aggregates(&agg, msg, &[&pk1, &pk2]).is_ok());
  // Secure verify uses different weighting, so naively
  // aggregated sigs should fail.
  assert!(secure_verify_aggregates(&agg, msg, &[&pk1, &pk2]).is_err());
}

/// Cancelling keys and signatures to the identity (`P + (-P)`) is rejected
/// under the IETF scheme, unlike the lenient legacy scheme: blst refuses an
/// infinity aggregate key, so verification fails for any message.
#[rstest]
#[case::signed_message([0x11u8; 32])]
#[case::unrelated_message([0x22u8; 32])]
fn identity_cancellation_is_rejected(ietf_sk0: SecretKey, #[case] verify_msg: [u8; 32]) {
  let sig = ietf_sk0.sign(&[0x11u8; 32]);
  let pk = ietf_sk0.public_key();

  // Flip the IETF sign bit (bit 5 of byte 0) to negate each point.
  let mut neg_sig_bytes = sig.to_bytes();
  neg_sig_bytes[0] ^= 0x20;
  let neg_sig = Signature::from_bytes(&neg_sig_bytes).unwrap();

  let mut neg_pk_bytes = pk.to_bytes();
  neg_pk_bytes[0] ^= 0x20;
  let neg_pk = PublicKey::from_bytes(&neg_pk_bytes).unwrap();

  // sig + (-sig) = identity signature; pk + (-pk) = identity key.
  let identity_sig = aggregate_sig(&[&sig, &neg_sig]).unwrap();

  // Verification fails regardless of the message.
  assert!(fast_verify_aggregates(&identity_sig, &verify_msg, &[&pk, &neg_pk]).is_err());
}

mod kat {
  use dash_dev::{vec_from_hex, Corpus};
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
    let vecs: Vec<AggregatePkVector> =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ietf_aggregate").vectors("aggregate_pk");

    for v in &vecs {
      let pks: Vec<dash_pkc::bls_ietf::PublicKey> = v
        .pks
        .iter()
        .map(|h| {
          let b: [u8; 48] = vec_from_hex(h).try_into().unwrap();
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
    let vecs: Vec<AggregateSigVector> =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ietf_aggregate").vectors("aggregate_sig");

    for v in &vecs {
      let sigs: Vec<dash_pkc::bls_ietf::Signature> = v
        .sigs
        .iter()
        .map(|h| {
          let b: [u8; 96] = vec_from_hex(h).try_into().unwrap();
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
    let vecs: Vec<AggregateSkVector> =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_aggregate").vectors("aggregate_sk");

    for v in &vecs {
      let sks: Vec<dash_pkc::bls_ietf::SecretKey> = v
        .sks
        .iter()
        .map(|h| {
          let b: [u8; 32] = vec_from_hex(h).try_into().unwrap();
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
    let vecs: Vec<SecureAggVector> =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ietf_secure_aggregate").vectors("secure_verify_aggregates");

    for v in &vecs {
      let msg = vec_from_hex(&v.msg);
      let pks: Vec<dash_pkc::bls_ietf::PublicKey> = v
        .pks
        .iter()
        .map(|h| {
          let b: [u8; 48] = vec_from_hex(h).try_into().unwrap();
          dash_pkc::bls_ietf::PublicKey::from_bytes(&b).unwrap()
        })
        .collect();

      let expected_agg: [u8; 96] = vec_from_hex(&v.agg_sig_secure).try_into().unwrap();
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
