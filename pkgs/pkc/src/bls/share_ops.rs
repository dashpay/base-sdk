//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold share types and secret-key splitting.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::secret_ops::BlsSecretKey;
use super::sig_basic::BlsSignature;
use super::BlsShareId;
use crate::prelude::*;

use dash_types::qtypestr;
use dash_types::type_id::Unencodable;
use rand_core::CryptoRng;

use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

/// Secret key share for threshold signing.
#[derive(Unencodable)]
pub struct BlsSkShare<S: BlsScheme> {
  id: BlsShareId,
  sk: BlsSecretKey<S>,
}

impl<S: BlsScheme> BlsSkShare<S> {
  /// Construct a secret key share from an ID and a secret key.
  pub fn new(id: BlsShareId, sk: BlsSecretKey<S>) -> Self {
    Self { id, sk }
  }

  /// Participant identifier.
  pub fn id(&self) -> &BlsShareId {
    &self.id
  }

  /// Sign a message of the scheme's message type, producing a signature share.
  pub fn sign(&self, msg: &S::Msg) -> BlsSigShare<S> {
    BlsSigShare {
      id: self.id,
      sig: self.sk.sign(msg),
    }
  }

  /// The underlying secret key.
  pub fn secret_key(&self) -> &BlsSecretKey<S> {
    &self.sk
  }
}

impl<S: BlsScheme> Clone for BlsSkShare<S> {
  fn clone(&self) -> Self {
    Self {
      id: self.id,
      sk: self.sk.clone(),
    }
  }
}

impl<S: BlsScheme> Debug for BlsSkShare<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, core::any::type_name::<Self>())?;
    write!(f, "(id={:?})", self.id)
  }
}

/// Signature share from a threshold participant.
#[derive(Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "", deserialize = "")))]
pub struct BlsSigShare<S: BlsScheme> {
  id: BlsShareId,
  sig: BlsSignature<S>,
}

impl<S: BlsScheme> BlsSigShare<S> {
  /// Construct a signature share from an ID and a signature.
  pub fn new(id: BlsShareId, sig: BlsSignature<S>) -> Self {
    Self { id, sig }
  }

  /// Participant identifier.
  pub fn id(&self) -> &BlsShareId {
    &self.id
  }

  /// The underlying signature.
  pub fn signature(&self) -> &BlsSignature<S> {
    &self.sig
  }
}

impl<S: BlsScheme> Clone for BlsSigShare<S> {
  fn clone(&self) -> Self {
    Self {
      id: self.id,
      sig: self.sig.clone(),
    }
  }
}

impl<S: BlsScheme> Debug for BlsSigShare<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    qtypestr(f, core::any::type_name::<Self>())?;
    write!(f, "(id={:?})", self.id)
  }
}

impl<S: BlsScheme> PartialEq for BlsSigShare<S> {
  fn eq(&self, other: &Self) -> bool {
    self.id == other.id && self.sig == other.sig
  }
}

impl<S: BlsScheme> Eq for BlsSigShare<S> {}

impl<S: BlsScheme> Hash for BlsSigShare<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.id.hash(state);
    state.write(&self.sig.to_bytes());
  }
}

impl<S: BlsScheme> BlsSecretKey<S> {
  /// Split this secret key into shares for the given participant IDs, requiring
  /// `threshold` shares to recover.
  ///
  /// # Errors
  ///
  /// Returns `ThresholdTooLarge` if `threshold` is below 2 or exceeds the
  /// number of ids, `InvalidShareId` if any id reduces to zero,
  /// `DuplicateShareId` if two ids collide mod the group order, or
  /// `InvalidSecretKey` if share generation fails.
  pub fn split(
    &self,
    threshold: usize,
    ids: &[BlsShareId],
    rng: &mut impl CryptoRng,
  ) -> Result<Vec<BlsSkShare<S>>, BlsError> {
    S::split_sk(&self.0, threshold, ids, rng, |id, inner| {
      BlsSkShare::new(id, BlsSecretKey::from_inner(inner))
    })
  }

  /// Derive a secret key share by evaluating the master secret polynomial at
  /// the given participant id.
  ///
  /// # Errors
  ///
  /// Returns `InvalidVerificationVector` when fewer than two master keys are
  /// given, `InvalidShareId` on a zero-reducing id, or `InvalidSecretKey`
  /// when the result is not a valid scalar.
  pub fn derive_share(master_sks: &[&Self], id: &BlsShareId) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerSk> = master_sks.iter().map(|sk| &sk.0).collect();
    S::derive_sk_share(&inner_refs, id).map(Self::from_inner)
  }
}

impl<S: BlsScheme> BlsPublicKey<S> {
  /// Derive a public key share by evaluating the master public key polynomial
  /// at the given participant id.
  ///
  /// # Errors
  ///
  /// Returns `InvalidVerificationVector` when fewer than two master keys are
  /// given, `InvalidShareId` on a zero-reducing id, or `InvalidPublicKey`
  /// when a coefficient or the result fails to decode.
  pub fn derive_share(master_pks: &[&Self], id: &BlsShareId) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerPk> = master_pks.iter().map(|pk| &pk.0).collect();
    S::derive_pk_share(&inner_refs, id).map(Self::from_inner)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{id_from_hex, make_id, sequential_ids, GROUP_ORDER, MSG_DEADBEEF, RSEED};
  use crate::bls::{BlsScChia, BlsScIetf};

  use cfg_if::cfg_if;
  use dash_dev::{arr_from_hex, Corpus, Value};
  use getrandom::SysRng;
  use hex_conservative::DisplayHex;
  use rand_core::UnwrapErr;
  use rstest::rstest;

  /// The scalar-field order `r + 1`, congruent to `1` mod `r`.
  fn group_order_plus_one() -> BlsShareId {
    let mut bytes = GROUP_ORDER;
    for b in bytes.iter_mut().rev() {
      let (v, carry) = b.overflowing_add(1);
      *b = v;
      if !carry {
        break;
      }
    }
    BlsShareId::from_bytes(bytes)
  }

  /// A 1-of-n split hands the master key to every participant, so a `threshold`
  /// below 2 is rejected; one above the participant count yields a quorum that
  /// can never sign.
  fn assert_invalid_thresholds_rejected<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&RSEED[0]).unwrap();
    let ids = sequential_ids(5);
    for threshold in [0, 1, ids.len() + 1] {
      assert!(matches!(
        sk.split(threshold, &ids, &mut UnwrapErr(SysRng)),
        Err(BlsError::ThresholdTooLarge)
      ));
    }
    assert!(matches!(
      sk.split(2, &[], &mut UnwrapErr(SysRng)),
      Err(BlsError::ThresholdTooLarge)
    ));
  }

  #[rstest]
  #[case::chia(assert_invalid_thresholds_rejected::<BlsScChia>)]
  #[case::ietf(assert_invalid_thresholds_rejected::<BlsScIetf>)]
  fn split_rejects_invalid_thresholds(#[case] assertion: fn()) {
    assertion();
  }

  /// An id congruent to zero mod `r` would make the share equal the master key,
  /// so both the zero hash and the group order are rejected.
  fn assert_zero_reducing_id_rejected<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&RSEED[0]).unwrap();

    let zero = BlsShareId::from_bytes([0u8; 32]);
    let ids = [make_id(1), zero];
    assert!(matches!(
      sk.split(2, &ids, &mut UnwrapErr(SysRng)),
      Err(BlsError::InvalidShareId)
    ));

    let order = BlsShareId::from_bytes(GROUP_ORDER);
    let ids = [make_id(1), order];
    assert!(matches!(
      sk.split(2, &ids, &mut UnwrapErr(SysRng)),
      Err(BlsError::InvalidShareId)
    ));
  }

  #[rstest]
  #[case::chia(assert_zero_reducing_id_rejected::<BlsScChia>)]
  #[case::ietf(assert_zero_reducing_id_rejected::<BlsScIetf>)]
  fn split_rejects_zero_reducing_ids(#[case] assertion: fn()) {
    assertion();
  }

  /// Two ids congruent mod `r` collide during interpolation, and a raw-byte
  /// duplicate check would miss `1` and `r + 1`.
  fn assert_congruent_ids_rejected<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&RSEED[0]).unwrap();
    let ids = [make_id(1), group_order_plus_one()];
    assert!(matches!(
      sk.split(2, &ids, &mut UnwrapErr(SysRng)),
      Err(BlsError::DuplicateShareId)
    ));
  }

  #[rstest]
  #[case::chia(assert_congruent_ids_rejected::<BlsScChia>)]
  #[case::ietf(assert_congruent_ids_rejected::<BlsScIetf>)]
  fn split_rejects_congruent_ids(#[case] assertion: fn()) {
    assertion();
  }

  /// The secret and public evaluations are the same polynomial, so a derived
  /// secret share must expose exactly the public share derived from the
  /// verification vector.
  fn assert_sk_share_matches_pk_share<S: BlsScheme>() {
    let master: Vec<BlsSecretKey<S>> = [&RSEED[0], &RSEED[1], &RSEED[2]]
      .iter()
      .map(|ikm| BlsSecretKey::<S>::generate(*ikm).unwrap())
      .collect();
    let master_refs: Vec<&BlsSecretKey<S>> = master.iter().collect();
    let vvec: Vec<BlsPublicKey<S>> = master.iter().map(BlsSecretKey::public_key).collect();
    let vvec_refs: Vec<&BlsPublicKey<S>> = vvec.iter().collect();

    for i in 1..=4u32 {
      let id = make_id(i);
      let sk_share = BlsSecretKey::<S>::derive_share(&master_refs, &id).unwrap();
      let pk_share = BlsPublicKey::<S>::derive_share(&vvec_refs, &id).unwrap();
      assert_eq!(sk_share.public_key(), pk_share);
    }

    assert!(matches!(
      BlsSecretKey::<S>::derive_share(&master_refs[..1], &make_id(1)),
      Err(BlsError::InvalidVerificationVector)
    ));
    assert!(matches!(
      BlsSecretKey::<S>::derive_share(&master_refs, &BlsShareId::from_bytes([0u8; 32])),
      Err(BlsError::InvalidShareId)
    ));
  }

  #[rstest]
  #[case::chia(assert_sk_share_matches_pk_share::<BlsScChia>)]
  #[case::ietf(assert_sk_share_matches_pk_share::<BlsScIetf>)]
  fn sk_share_matches_pk_share(#[case] assertion: fn()) {
    assertion();
  }

  /// Evaluating the verification-vector polynomial needs at least two
  /// coefficients, so a single master key is rejected.
  fn assert_derive_share_rejects_short_vv<S: BlsScheme>() {
    let pk = BlsSecretKey::<S>::generate(&RSEED[0]).unwrap().public_key();
    assert!(matches!(
      BlsPublicKey::<S>::derive_share(&[&pk], &make_id(1)),
      Err(BlsError::InvalidVerificationVector)
    ));
  }

  #[rstest]
  #[case::chia(assert_derive_share_rejects_short_vv::<BlsScChia>)]
  #[case::ietf(assert_derive_share_rejects_short_vv::<BlsScIetf>)]
  fn derive_share_rejects_short_verification_vector(#[case] assertion: fn()) {
    assertion();
  }

  /// End-to-end quorum DKG validation against reference vectors, exercising the
  /// full flow: contribute -> verify -> commit -> finalize.
  fn assert_llmq_contribute_vvec<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();
    let t = f["inputs"]["t"].as_u64().unwrap() as usize;

    for c in f["contribute"].as_array().unwrap() {
      let vvec: Vec<&str> = c["vvec"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
      assert_eq!(vvec.len(), t, "vvec must hold one coefficient per threshold");

      for pk_hex in &vvec {
        assert!(BlsPublicKey::<S>::from_bytes(&arr_from_hex(pk_hex)).is_ok());
      }
    }
  }

  #[rstest]
  #[case::chia("chia", assert_llmq_contribute_vvec::<BlsScChia>)]
  #[case::ietf("ietf", assert_llmq_contribute_vvec::<BlsScIetf>)]
  fn llmq_contribute_vvec(#[case] scheme: &str, #[case] assertion: fn(&str)) {
    assertion(scheme);
  }

  fn assert_llmq_contribute_sk_shares<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();
    let n = f["inputs"]["n"].as_u64().unwrap() as usize;

    for c in f["contribute"].as_array().unwrap() {
      let shares = c["sk_shares"].as_array().unwrap();
      assert_eq!(shares.len(), n);
      for s in shares {
        assert!(BlsSecretKey::<S>::from_bytes(&arr_from_hex(s.as_str().unwrap())).is_ok());
      }
    }
  }

  #[rstest]
  #[case::chia("chia", assert_llmq_contribute_sk_shares::<BlsScChia>)]
  #[case::ietf("ietf", assert_llmq_contribute_sk_shares::<BlsScIetf>)]
  fn llmq_contribute_sk_shares(#[case] scheme: &str, #[case] assertion: fn(&str)) {
    assertion(scheme);
  }

  fn assert_llmq_verify_contributions<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();
    let member_ids: Vec<String> = f["inputs"]["member_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    for v in f["verify"].as_array().unwrap() {
      let member_idx = v["member_idx"].as_u64().unwrap() as usize;
      let received_vvecs = v["received_vvecs"].as_array().unwrap();
      let received_sks = v["received_sk_contributions"].as_array().unwrap();
      let results = v["verification_results"].as_array().unwrap();

      for (contrib_idx, ((vvec_arr, sk_hex), expected)) in received_vvecs
        .iter()
        .zip(received_sks.iter())
        .zip(results.iter())
        .enumerate()
      {
        let vvec: Vec<BlsPublicKey<S>> = vvec_arr
          .as_array()
          .unwrap()
          .iter()
          .map(|v| BlsPublicKey::<S>::from_bytes(&arr_from_hex(v.as_str().unwrap())).unwrap())
          .collect();
        let vvec_refs: Vec<&BlsPublicKey<S>> = vvec.iter().collect();

        let sk_share = BlsSecretKey::<S>::from_bytes(&arr_from_hex(sk_hex.as_str().unwrap())).unwrap();
        let pk_from_share = sk_share.public_key();

        let member_id = id_from_hex(&member_ids[member_idx]);
        let pk_from_vvec = BlsPublicKey::derive_share(&vvec_refs, &member_id).unwrap();

        let matches = pk_from_share.to_bytes() == pk_from_vvec.to_bytes();
        assert_eq!(
          matches,
          expected.as_bool().unwrap(),
          "verification mismatch for member {} from contributor {}",
          member_idx,
          contrib_idx,
        );
      }
    }
  }

  #[rstest]
  #[case::chia("chia", assert_llmq_verify_contributions::<BlsScChia>)]
  #[case::ietf("ietf", assert_llmq_verify_contributions::<BlsScIetf>)]
  fn llmq_verify_contributions(#[case] scheme: &str, #[case] assertion: fn(&str)) {
    assertion(scheme);
  }

  fn assert_llmq_commit_quorum_key<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();

    let commits = f["commit"].as_array().unwrap();
    let expected_qpk = commits[0]["quorum_public_key"].as_str().unwrap();

    for c in commits {
      assert_eq!(
        c["quorum_public_key"].as_str().unwrap(),
        expected_qpk,
        "quorum pk disagreement at member {}",
        c["member_idx"],
      );
      let qvvec = c["quorum_vvec"].as_array().unwrap();
      assert_eq!(qvvec[0].as_str().unwrap(), expected_qpk);
    }

    // Reconstruct the quorum pk by aggregating each member's vvec[0].
    let contributions = f["contribute"].as_array().unwrap();
    let member_pks: Vec<BlsPublicKey<S>> = contributions
      .iter()
      .map(|c| BlsPublicKey::<S>::from_bytes(&arr_from_hex(c["vvec"][0].as_str().unwrap())).unwrap())
      .collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = member_pks.iter().collect();
    let agg_pk = BlsPublicKey::aggregate(&pk_refs).unwrap();
    assert_eq!(agg_pk.to_bytes().to_lower_hex_string(), expected_qpk);
  }

  #[rstest]
  #[case::chia("chia", assert_llmq_commit_quorum_key::<BlsScChia>)]
  #[case::ietf("ietf", assert_llmq_commit_quorum_key::<BlsScIetf>)]
  fn llmq_commit_quorum_key(#[case] scheme: &str, #[case] assertion: fn(&str)) {
    assertion(scheme);
  }

  fn assert_llmq_commit_sk_share<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();

    // Each member's committed sk_share is the sum of the sk_contributions it
    // received from every contributor.
    for (member_idx, c) in f["commit"].as_array().unwrap().iter().enumerate() {
      let expected_share = c["sk_share"].as_str().unwrap();

      let mut received: Vec<BlsSecretKey<S>> = Vec::new();
      for contrib in f["contribute"].as_array().unwrap() {
        let sk_hex = contrib["sk_shares"][member_idx].as_str().unwrap();
        received.push(BlsSecretKey::<S>::from_bytes(&arr_from_hex(sk_hex)).unwrap());
      }

      let refs: Vec<&BlsSecretKey<S>> = received.iter().collect();
      let agg = BlsSecretKey::aggregate(&refs).unwrap();
      assert_eq!(
        agg.to_bytes().to_lower_hex_string(),
        expected_share,
        "sk_share mismatch for member {}",
        member_idx,
      );
    }
  }

  #[rstest]
  #[case::chia("chia", assert_llmq_commit_sk_share::<BlsScChia>)]
  #[case::ietf("ietf", assert_llmq_commit_sk_share::<BlsScIetf>)]
  fn llmq_commit_sk_share(#[case] scheme: &str, #[case] assertion: fn(&str)) {
    assertion(scheme);
  }

  fn assert_llmq_commit_sig<S: BlsScheme>(scheme: &str, hash_field: &str, label: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();

    for c in f["commit"].as_array().unwrap() {
      let sk_share = BlsSecretKey::<S>::from_bytes(&arr_from_hex(c["sk_share"].as_str().unwrap())).unwrap();
      let msg: [u8; 32] = arr_from_hex(c[hash_field].as_str().unwrap());

      let sig = sk_share.sign(S::msg_ref(&msg));
      let pk = sk_share.public_key();
      assert!(
        sig.verify(S::msg_ref(&msg), &pk).is_ok(),
        "{} failed self-verification at member {}",
        label,
        c["member_idx"],
      );
    }
  }

  #[rstest]
  #[case::chia_member("chia", assert_llmq_commit_sig::<BlsScChia>, "commitment_hash", "member_sig")]
  #[case::chia_quorum("chia", assert_llmq_commit_sig::<BlsScChia>, "quorum_hash", "quorum_sig_share")]
  #[case::ietf_member("ietf", assert_llmq_commit_sig::<BlsScIetf>, "commitment_hash", "member_sig")]
  #[case::ietf_quorum("ietf", assert_llmq_commit_sig::<BlsScIetf>, "quorum_hash", "quorum_sig_share")]
  fn llmq_commit_sig(
    #[case] scheme: &str,
    #[case] assertion: fn(&str, &str, &str),
    #[case] hash_field: &str,
    #[case] label: &str,
  ) {
    assertion(scheme, hash_field, label);
  }

  fn assert_llmq_finalize_recover_quorum_sig<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();
    let fin = &f["finalize"];
    let commits = f["commit"].as_array().unwrap();

    let member_ids: Vec<String> = f["inputs"]["member_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    let signer_ids: Vec<String> = fin["signer_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    let quorum_hash: [u8; 32] = arr_from_hex(fin["quorum_hash"].as_str().unwrap());
    let sig_shares: Vec<BlsSigShare<S>> = signer_ids
      .iter()
      .map(|sid| {
        let member_id = BlsShareId::from_bytes(arr_from_hex::<32>(sid));
        let sid_display = member_id.to_string();
        let idx = member_ids.iter().position(|m| *m == sid_display).unwrap();
        let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(commits[idx]["sk_share"].as_str().unwrap())).unwrap();
        BlsSkShare::new(member_id, sk).sign(S::msg_ref(&quorum_hash))
      })
      .collect();

    let share_refs: Vec<&BlsSigShare<S>> = sig_shares.iter().collect();
    let recovered = BlsSignature::recover(&share_refs).unwrap();

    let quorum_pk =
      BlsPublicKey::<S>::from_bytes(&arr_from_hex(commits[0]["quorum_public_key"].as_str().unwrap())).unwrap();
    assert!(
      recovered.verify(S::msg_ref(&quorum_hash), &quorum_pk).is_ok(),
      "recovered quorum sig failed verification"
    );

    // Cross-check: recovery from all members should match the subset recovery.
    let all_ids: Vec<BlsShareId> = member_ids.iter().map(|mid| id_from_hex(mid)).collect();
    let all_shares: Vec<BlsSigShare<S>> = commits
      .iter()
      .zip(all_ids.iter())
      .map(|(c, id)| {
        let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(c["sk_share"].as_str().unwrap())).unwrap();
        BlsSkShare::new(*id, sk).sign(S::msg_ref(&quorum_hash))
      })
      .collect();
    let all_refs: Vec<&BlsSigShare<S>> = all_shares.iter().collect();
    let recovered_all = BlsSignature::recover(&all_refs).unwrap();
    assert_eq!(
      recovered.to_bytes(),
      recovered_all.to_bytes(),
      "recovery from subset and full set differ"
    );
  }

  #[rstest]
  #[case::chia("chia", assert_llmq_finalize_recover_quorum_sig::<BlsScChia>)]
  #[case::ietf("ietf", assert_llmq_finalize_recover_quorum_sig::<BlsScIetf>)]
  fn llmq_finalize_recover_quorum_sig(#[case] scheme: &str, #[case] assertion: fn(&str)) {
    assertion(scheme);
  }

  fn assert_llmq_finalize_aggregated_member_sigs<S: BlsScheme>(scheme: &str) {
    let f: Value = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_llmq_100")
      .scope(scheme)
      .into_value();
    let commits = f["commit"].as_array().unwrap();

    // Re-sign the commitment hash with each member's sk_share, then aggregate.
    let commitment_hash: [u8; 32] = arr_from_hex(commits[0]["commitment_hash"].as_str().unwrap());

    let member_sigs: Vec<BlsSignature<S>> = commits
      .iter()
      .map(|c| {
        let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(c["sk_share"].as_str().unwrap())).unwrap();
        sk.sign(S::msg_ref(&commitment_hash))
      })
      .collect();
    let sig_refs: Vec<&BlsSignature<S>> = member_sigs.iter().collect();
    let agg_sig = BlsSignature::aggregate(&sig_refs).unwrap();

    let member_pks: Vec<BlsPublicKey<S>> = commits
      .iter()
      .map(|c| {
        let sk = BlsSecretKey::<S>::from_bytes(&arr_from_hex(c["sk_share"].as_str().unwrap())).unwrap();
        sk.public_key()
      })
      .collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = member_pks.iter().collect();

    assert!(
      agg_sig
        .fast_verify_aggregates(S::msg_ref(&commitment_hash), &pk_refs)
        .is_ok(),
      "aggregated member sigs failed fast_verify"
    );
  }

  #[rstest]
  #[case::chia("chia", assert_llmq_finalize_aggregated_member_sigs::<BlsScChia>)]
  #[case::ietf("ietf", assert_llmq_finalize_aggregated_member_sigs::<BlsScIetf>)]
  fn llmq_finalize_aggregated_member_sigs(#[case] scheme: &str, #[case] assertion: fn(&str)) {
    assertion(scheme);
  }

  /// `Hash` wants a `core::hash::Hasher`, which is not the interface the
  /// crate's digests expose and which `no_std` doesn't provide a default for.
  struct TestHasher(u64);

  impl Hasher for TestHasher {
    fn finish(&self) -> u64 {
      self.0
    }

    fn write(&mut self, bytes: &[u8]) {
      for byte in bytes {
        self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
      }
    }
  }

  fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = TestHasher(0xcbf2_9ce4_8422_2325);
    value.hash(&mut hasher);
    hasher.finish()
  }

  /// Both impls are written out rather than derived, so nothing stops one from
  /// quietly dropping a field. Shares agreeing on id and signature compare and
  /// hash alike; changing either separates them.
  fn assert_share_eq_and_hash<S: BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&RSEED[0]).unwrap();
    let other_sk = BlsSecretKey::<S>::generate(&RSEED[1]).unwrap();
    let msg = S::msg_ref(&MSG_DEADBEEF);

    let share = BlsSkShare::new(make_id(1), sk.clone()).sign(msg);
    let same = BlsSkShare::new(make_id(1), sk.clone()).sign(msg);

    // One field varies at a time, or a dropped field would hide behind the other
    // still differing.
    let other_id = BlsSkShare::new(make_id(2), sk).sign(msg);
    let other_sig = BlsSkShare::new(make_id(1), other_sk).sign(msg);

    assert_eq!(share, same);
    assert_eq!(hash_of(&share), hash_of(&same));

    assert_ne!(share, other_id);
    assert_ne!(hash_of(&share), hash_of(&other_id));

    assert_ne!(share, other_sig);
    assert_ne!(hash_of(&share), hash_of(&other_sig));
  }

  #[rstest]
  #[case::chia(assert_share_eq_and_hash::<BlsScChia>)]
  #[case::ietf(assert_share_eq_and_hash::<BlsScIetf>)]
  fn share_equality_and_hashing(#[case] assertion: fn()) {
    assertion();
  }

  cfg_if! {
    if #[cfg(feature = "serde")] {
      use dash_dev::assert_json_rt;

      fn assert_share_serde_roundtrip<S: BlsScheme>() {
        let sk = BlsSecretKey::<S>::generate(&RSEED[0]).unwrap();
        assert_json_rt(&BlsSkShare::new(make_id(1), sk).sign(S::msg_ref(&MSG_DEADBEEF)));
      }

      #[rstest]
      #[case::chia(assert_share_serde_roundtrip::<BlsScChia>)]
      #[case::ietf(assert_share_serde_roundtrip::<BlsScIetf>)]
      fn share_serde_roundtrip(#[case] assertion: fn()) {
        assertion();
      }
    }
  }
}
