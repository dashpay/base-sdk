//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS signature aggregation and aggregate verification.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
use super::BlsScIetf;
use crate::prelude::*;

impl<S: BlsScheme> BlsSignature<S> {
  /// Aggregate multiple signatures into one.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no signatures are given, or
  /// `InvalidSignature` when a signature fails to aggregate.
  pub fn aggregate(sigs: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerSig> = sigs.iter().map(|s| &s.0).collect();
    S::aggregate_sig(&inner_refs).map(Self::from_inner)
  }

  /// Verify an aggregated signature where every signer signed
  /// the same message.
  ///
  /// Binds only the sum of `pks`, so a key chosen after seeing an honest one
  /// can cancel it out. Every key must already be bound to its holder, by a
  /// proof of possession or by provenance.
  ///
  /// Without such a binding, use [`Self::secure_verify_aggregates`], which
  /// weights each key.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, or `VerifyFailed` on
  /// mismatch.
  pub fn fast_verify_aggregates(&self, msg: &S::Msg, pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::fast_verify_aggregates(&self.0, msg, &inner_pks)
  }

  /// Securely aggregate and verify signatures with public-key
  /// weighting.
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` when no keys are given, `InvalidPublicKey`
  /// when a key fails to decode, or `VerifyFailed` on mismatch.
  pub fn secure_verify_aggregates(&self, msg: &S::Msg, pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::secure_verify_aggregates(&self.0, msg, &inner_pks)
  }
}

impl BlsSignature<BlsScIetf> {
  /// Verify an aggregated signature where each signer signed a distinct
  /// message.
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` when the message and key counts differ,
  /// `EmptyAggregation` when no keys are given, or `VerifyFailed` on
  /// mismatch.
  pub fn verify_aggregates(&self, msgs: &[&[u8]], pks: &[&BlsPublicKey<BlsScIetf>]) -> Result<(), BlsError> {
    let inner_pks: Vec<_> = pks.iter().map(|k| &k.0).collect();
    BlsScIetf::verify_aggregates(&self.0, msgs, &inner_pks)
  }
}

#[cfg(all(test, feature = "tests"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::secret_ops::BlsSecretKey;
  use crate::bls::tests::{MSG_DEADBEEF, SEED_0, SEED_1};
  use crate::bls::{BlsScChia, BlsScIetf};

  use dash_dev::{arr_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use rstest::rstest;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SecureVec {
    msg: String,
    pks: Vec<String>,
    agg_sig_secure: String,
  }

  #[derive(Deserialize)]
  struct AggSigVec {
    sigs: Vec<String>,
    agg_sig: String,
  }

  fn assert_aggregate_same_message<S: BlsScheme>() {
    let sk1 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let sk2 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
    let sig1 = sk1.sign(S::msg_ref(&MSG_DEADBEEF));
    let sig2 = sk2.sign(S::msg_ref(&MSG_DEADBEEF));

    let agg = BlsSignature::<S>::aggregate(&[&sig1, &sig2]).unwrap();
    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();

    let msg = S::msg_ref(&MSG_DEADBEEF);
    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk2]).is_ok());
    // A key not in the set must make verification fail.
    let pk3 = BlsSecretKey::<S>::generate(&[9u8; 32]).unwrap().public_key();
    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk3]).is_err());
    // Rogue-key resistance: a naive aggregate must not pass weighted verify.
    assert!(agg.secure_verify_aggregates(msg, &[&pk1, &pk2]).is_err());
  }

  #[rstest]
  #[case::chia(assert_aggregate_same_message::<BlsScChia>)]
  #[case::ietf(assert_aggregate_same_message::<BlsScIetf>)]
  fn aggregate_and_verify_same_message(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_secure_verify<S: BlsScheme>(corpus: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus);
    let vecs: Vec<SecureVec> = corpus.vectors("secure_verify_aggregates");
    for v in &vecs {
      let pks: Vec<BlsPublicKey<S>> = v
        .pks
        .iter()
        .map(|pk| BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk)).unwrap())
        .collect();
      let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
      let agg = BlsSignature::<S>::from_bytes(&arr_from_hex(&v.agg_sig_secure)).unwrap();
      let msg: [u8; 32] = arr_from_hex(&v.msg);
      assert!(agg.secure_verify_aggregates(S::msg_ref(&msg), &pk_refs).is_ok());
    }
  }

  #[rstest]
  #[case::chia(assert_secure_verify::<BlsScChia>, "bls_chia_secure_aggregate")]
  #[case::ietf(assert_secure_verify::<BlsScIetf>, "bls_ietf_secure_aggregate")]
  fn secure_verify_matches_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  #[rstest]
  fn ietf_verify_distinct_messages() {
    let sk1 = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let sk2 = BlsSecretKey::<BlsScIetf>::generate(&SEED_1).unwrap();

    let msg1: &[u8] = b"first message";
    let msg2: &[u8] = b"second message";
    let sig1 = sk1.sign(msg1);
    let sig2 = sk2.sign(msg2);
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    assert!(agg.verify_aggregates(&[msg1, msg2], &[&pk1, &pk2]).is_ok());
    assert!(agg.verify_aggregates(&[msg2, msg1], &[&pk1, &pk2]).is_err());
  }

  /// An empty aggregate has no signers to bind, so both aggregation entry
  /// points reject it rather than returning the identity.
  fn assert_empty_aggregation_rejected<S: BlsScheme>() {
    let pks: [&BlsPublicKey<S>; 0] = [];
    let sigs: [&BlsSignature<S>; 0] = [];
    assert!(BlsPublicKey::<S>::aggregate(&pks).is_err());
    assert!(BlsSignature::<S>::aggregate(&sigs).is_err());
  }

  #[rstest]
  #[case::chia(assert_empty_aggregation_rejected::<BlsScChia>)]
  #[case::ietf(assert_empty_aggregation_rejected::<BlsScIetf>)]
  fn aggregate_empty_fails(#[case] assertion: fn()) {
    assertion();
  }

  /// Aggregation is a group sum, so neither the aggregate nor the verification
  /// may depend on the order the caller supplies.
  fn assert_order_independent<S: BlsScheme>() {
    let sks: Vec<BlsSecretKey<S>> = [SEED_0, SEED_1, [2u8; 32]]
      .iter()
      .map(|seed| BlsSecretKey::<S>::generate(seed).unwrap())
      .collect();
    let sigs: Vec<BlsSignature<S>> = sks.iter().map(|sk| sk.sign(S::msg_ref(&MSG_DEADBEEF))).collect();
    let pks: Vec<BlsPublicKey<S>> = sks.iter().map(BlsSecretKey::public_key).collect();

    let straight = BlsSignature::<S>::aggregate(&[&sigs[0], &sigs[1], &sigs[2]]).unwrap();
    let rotated = BlsSignature::<S>::aggregate(&[&sigs[2], &sigs[0], &sigs[1]]).unwrap();
    assert_eq!(straight, rotated);

    let msg = S::msg_ref(&MSG_DEADBEEF);
    assert!(straight
      .fast_verify_aggregates(msg, &[&pks[0], &pks[1], &pks[2]])
      .is_ok());
    assert!(straight
      .fast_verify_aggregates(msg, &[&pks[2], &pks[0], &pks[1]])
      .is_ok());
  }

  #[rstest]
  #[case::chia(assert_order_independent::<BlsScChia>)]
  #[case::ietf(assert_order_independent::<BlsScIetf>)]
  fn aggregate_order_independent(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_aggregate_vectors<S: BlsScheme>(corpus: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), corpus);
    let vecs: Vec<AggSigVec> = corpus.vectors("aggregate_sig");

    for v in &vecs {
      let sigs: Vec<BlsSignature<S>> = v
        .sigs
        .iter()
        .map(|sig| BlsSignature::<S>::from_bytes(&arr_from_hex(sig)).unwrap())
        .collect();
      let refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
      let agg = BlsSignature::<S>::aggregate(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig);
    }
  }

  #[rstest]
  #[case::chia(assert_aggregate_vectors::<BlsScChia>, "bls_chia_aggregate")]
  #[case::ietf(assert_aggregate_vectors::<BlsScIetf>, "bls_ietf_aggregate")]
  fn aggregate_matches_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  /// Aggregating a point with its own negation cancels to the identity, which
  /// then verifies against any message at all. The legacy scheme accepts that,
  /// and consensus depends on it continuing to; the IETF scheme rejects it.
  /// The sign bit sits at bit 7 for legacy and bit 5 for IETF.
  fn assert_identity_cancellation<S: BlsScheme>(sign_bit: u8, accepted: bool) {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let signed = [0x11u8; 32];
    let sig = sk.sign(S::msg_ref(&signed));
    let pk = sk.public_key();

    let mut neg_sig_bytes = sig.to_bytes();
    neg_sig_bytes[0] ^= sign_bit;
    let neg_sig = BlsSignature::<S>::from_bytes(&neg_sig_bytes).unwrap();

    let mut neg_pk_bytes = pk.to_bytes();
    neg_pk_bytes[0] ^= sign_bit;
    let neg_pk = BlsPublicKey::<S>::from_bytes(&neg_pk_bytes).unwrap();

    let identity = BlsSignature::<S>::aggregate(&[&sig, &neg_sig]).unwrap();
    // The outcome must not depend on the message, signed or otherwise.
    for msg in [signed, MSG_DEADBEEF] {
      let res = identity.fast_verify_aggregates(S::msg_ref(&msg), &[&pk, &neg_pk]);
      assert_eq!(res.is_ok(), accepted, "identity aggregate over {msg:?}");
    }
  }

  #[rstest]
  #[case::chia(assert_identity_cancellation::<BlsScChia>, 0x80, true)]
  #[case::ietf(assert_identity_cancellation::<BlsScIetf>, 0x20, false)]
  fn identity_cancellation_follows_scheme(
    #[case] assertion: fn(u8, bool),
    #[case] sign_bit: u8,
    #[case] accepted: bool,
  ) {
    assertion(sign_bit, accepted);
  }
}
