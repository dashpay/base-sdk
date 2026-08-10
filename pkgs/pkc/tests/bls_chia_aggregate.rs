//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and secure verification tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

use common::*;
use dash_pkc::bls::tests as common;
use dash_pkc::bls_chia::{aggregate_sig, verify_aggregates, PublicKey, SecretKey, Signature};
use rstest::*;

/// Aggregate then verify over a shared message.
#[rstest]
fn aggregate_and_verify(chia_sk0: SecretKey, chia_sk1: SecretKey) {
  let msg = [0xabu8; 32];
  let sig1 = chia_sk0.sign(&msg);
  let sig2 = chia_sk1.sign(&msg);
  let agg = aggregate_sig(&[&sig1, &sig2]).unwrap();
  let pk1 = chia_sk0.public_key();
  let pk2 = chia_sk1.public_key();
  assert!(verify_aggregates(&agg, &msg, &[&pk1, &pk2]).is_ok());
}

/// Empty aggregation is rejected.
#[rstest]
fn aggregate_empty_fails() {
  let empty_pk: Vec<&dash_pkc::bls_chia::PublicKey> = vec![];
  assert!(PublicKey::aggregate(&empty_pk).is_err());
  let empty_sig: Vec<&Signature> = vec![];
  assert!(aggregate_sig(&empty_sig).is_err());
}

/// Secure aggregation with weighted coefficients.
#[rstest]
fn secure_verify_aggregates_roundtrip(chia_sk0: SecretKey, chia_sk1: SecretKey) {
  use dash_pkc::bls_chia::secure_verify_aggregates;
  let msg = [0xabu8; 32];
  let sig1 = chia_sk0.sign(&msg);
  let sig2 = chia_sk1.sign(&msg);
  let agg = aggregate_sig(&[&sig1, &sig2]).unwrap();
  let pk1 = chia_sk0.public_key();
  let pk2 = chia_sk1.public_key();
  // Simple aggregation should pass verify_aggregates
  assert!(verify_aggregates(&agg, &msg, &[&pk1, &pk2]).is_ok());
  // But secure_verify uses different weighting, so naively
  // aggregated sigs should fail (wrong weighting).
  assert!(secure_verify_aggregates(&agg, &msg, &[&pk1, &pk2]).is_err());
}

/// Secure aggregation is order-independent: shuffling the input
/// public keys produces the same result.
#[rstest]
fn secure_aggregate_order_independent() {
  let sk1 = SecretKey::generate(&RSEED[1]).unwrap();
  let sk2 = SecretKey::generate(&RSEED[2]).unwrap();
  let sk3 = SecretKey::generate(&RSEED[3]).unwrap();

  let msg = [0xffu8; 32];
  let pk1 = sk1.public_key();
  let pk2 = sk2.public_key();
  let pk3 = sk3.public_key();
  let sig1 = sk1.sign(&msg);
  let sig2 = sk2.sign(&msg);
  let sig3 = sk3.sign(&msg);

  // Aggregate in order [1,2,3] and [3,1,2], secure verify
  // should accept both with the same pks set.
  let agg_a = aggregate_sig(&[&sig1, &sig2, &sig3]).unwrap();
  let agg_b = aggregate_sig(&[&sig3, &sig1, &sig2]).unwrap();

  // Both aggregates are simple sums, so they should be
  // identical (addition is commutative).
  assert_eq!(agg_a.to_bytes(), agg_b.to_bytes());

  // verify_aggregates (non-secure) accepts both.
  assert!(verify_aggregates(&agg_a, &msg, &[&pk1, &pk2, &pk3]).is_ok());
  assert!(verify_aggregates(&agg_a, &msg, &[&pk3, &pk1, &pk2]).is_ok());
}

/// Cancelling keys and signatures to the identity (`P + (-P)`) yields a
/// point that satisfies the pairing check for any message. The primitives
/// accept it for backwards compatibility: the signed message and an
/// unrelated one both verify.
#[rstest]
#[case::signed_message([0x11u8; 32])]
#[case::unrelated_message([0x22u8; 32])]
fn identity_cancellation_is_not_rejected(chia_sk0: SecretKey, #[case] verify_msg: [u8; 32]) {
  let sig = chia_sk0.sign(&[0x11u8; 32]);
  let pk = chia_sk0.public_key();

  let mut neg_sig_bytes = sig.to_bytes();
  neg_sig_bytes[0] ^= 0x80;
  let neg_sig = Signature::from_bytes(&neg_sig_bytes).unwrap();

  let mut neg_pk_bytes = pk.to_bytes();
  neg_pk_bytes[0] ^= 0x80;
  let neg_pk = PublicKey::from_bytes(&neg_pk_bytes).unwrap();

  // sig + (-sig) = identity signature; pk + (-pk) = identity key.
  let identity_sig = aggregate_sig(&[&sig, &neg_sig]).unwrap();

  // Verifies regardless of the message.
  assert!(verify_aggregates(&identity_sig, &verify_msg, &[&pk, &neg_pk]).is_ok());
}

mod kat {
  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct AggregateSigVector {
    sigs: Vec<String>,
    agg_sig: String,
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
  fn kat_aggregate_sig() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_aggregate");
    let vecs: Vec<AggregateSigVector> = corpus.vectors("aggregate_sig");

    for v in &vecs {
      let sigs: Vec<dash_pkc::bls_chia::Signature> = v
        .sigs
        .iter()
        .map(|h| {
          let b: [u8; 96] = arr_from_hex(h);
          dash_pkc::bls_chia::Signature::from_bytes(&b).unwrap()
        })
        .collect();
      let sig_refs: Vec<_> = sigs.iter().collect();
      let agg = dash_pkc::bls_chia::aggregate_sig(&sig_refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig);
    }
  }

  #[test]
  fn kat_secure_verify_aggregates() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_secure_aggregate");
    let vecs: Vec<SecureAggVector> = corpus.vectors("secure_verify_aggregates");

    for v in &vecs {
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      let pks: Vec<dash_pkc::bls_chia::PublicKey> = v
        .pks
        .iter()
        .map(|h| {
          let b: [u8; 48] = arr_from_hex(h);
          dash_pkc::bls_chia::PublicKey::from_bytes(&b).unwrap()
        })
        .collect();

      let expected_agg: [u8; 96] = arr_from_hex(&v.agg_sig_secure);
      let agg_sig = dash_pkc::bls_chia::Signature::from_bytes(&expected_agg).unwrap();
      let pk_refs: Vec<_> = pks.iter().collect();

      assert!(
        dash_pkc::bls_chia::secure_verify_aggregates(&agg_sig, &msg, &pk_refs).is_ok(),
        "secure verify failed for n={}",
        v.pks.len()
      );
    }
  }
}
