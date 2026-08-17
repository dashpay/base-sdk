//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Basic BLS scheme implementation.

use super::blst_ffi::{G1Affine, G2Affine, G1, G2};
use super::error::BlsError;
use super::scheme_ops::{verify_ok, BlsScheme};
use super::schemes::BlsScIetf;
use super::sig_id::BlsSigId;
use crate::prelude::*;

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};

/// Domain separation tag for the basic (NUL) signature scheme.
const DST_BASIC: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Domain separation tag for signatures in the proof-of-possession scheme.
const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separation tag for proofs of possession.
const DST_POP_PROVE: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

impl BlsScheme for BlsScIetf {
  type InnerSk = SecretKey;
  type InnerPk = PublicKey;
  type InnerSig = Signature;
  type Msg = [u8];

  /// Derive via draft-03 keygen.
  fn generate(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    SecretKey::key_gen_v3(ikm, &[]).map_err(|_| BlsError::InvalidKeyMaterial)
  }

  /// Parse the 32-byte scalar through blst.
  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    SecretKey::from_bytes(b).map_err(|_| BlsError::InvalidSecretKey)
  }

  /// Emit the scalar as big-endian bytes.
  fn sk_to_bytes(sk: &Self::InnerSk) -> [u8; 32] {
    sk.to_bytes()
  }

  /// Map the secret key to its G1 public key.
  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk {
    sk.sk_to_pk()
  }

  /// Wipe the scalar limbs.
  fn zeroize_sk(sk: &mut Self::InnerSk) {
    // blst's SecretKey wipes itself on drop but exposes no in-place wipe,
    // so assign over it. The old value drops, dropping is the wipe.
    *sk = SecretKey::default();
  }

  /// Decode the compressed G1 point and run `validate`.
  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError> {
    let pk = PublicKey::from_bytes(b).map_err(|_| BlsError::InvalidPublicKey)?;
    // blst `from_bytes` checks only encoding and curve; validate also
    // rejects the identity and non-prime-order points before use.
    pk.validate().map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(pk)
  }

  /// Compress the G1 point to 48 bytes.
  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    pk.compress()
  }

  /// Decompress the blst public key into a projective G1 point.
  fn pk_to_g1(pk: &Self::InnerPk) -> Result<G1, BlsError> {
    let aff = G1Affine::uncompress(&pk.compress()).map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(aff.to_projective())
  }

  /// Re-encode the projective point and parse it back through `validate`.
  fn g1_to_pk(point: G1) -> Result<Self::InnerPk, BlsError> {
    Self::pk_from_bytes(&point.to_affine().compress())
  }

  /// Uncompress the standard encoding without re-running `validate`.
  ///
  /// The bytes come from `pk_to_bytes` on a key that `pk_from_bytes` already
  /// validated, so a second subgroup check would only repeat that work.
  fn secure_agg_point(pk_bytes: &[u8; 48]) -> Result<G1, BlsError> {
    let aff = G1Affine::uncompress(pk_bytes).map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(aff.to_projective())
  }

  /// Decode the compressed G2 point and run `validate`.
  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    let sig = Signature::from_bytes(b).map_err(|_| BlsError::InvalidSignature)?;
    // blst `from_bytes` checks only encoding and curve; validate also
    // rejects the identity and non-prime-order points before use.
    sig.validate(true).map_err(|_| BlsError::InvalidSignature)?;
    Ok(sig)
  }

  /// Compress the G2 point to 96 bytes.
  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    sig.compress()
  }

  /// Decompress the blst signature into a projective G2 point.
  fn sig_to_g2(sig: &Self::InnerSig) -> Result<G2, BlsError> {
    let aff = G2Affine::uncompress(&Self::sig_to_bytes(sig)).map_err(|_| BlsError::InvalidSignature)?;
    Ok(aff.to_projective())
  }

  /// Re-encode the projective point and parse it back through `validate`.
  fn g2_to_sig(point: G2) -> Result<Self::InnerSig, BlsError> {
    Self::sig_from_bytes(&point.to_affine().compress())
  }

  /// Sign with the basic-scheme DST.
  fn sign(sk: &Self::InnerSk, msg: &Self::Msg) -> Self::InnerSig {
    sk.sign(msg, DST_BASIC, &[])
  }

  /// Verify against the basic-scheme DST.
  fn verify(sig: &Self::InnerSig, msg: &Self::Msg, pk: &Self::InnerPk) -> Result<(), BlsError> {
    verify_ok(sig.verify(true, msg, DST_BASIC, &[], pk, true))
  }

  /// IETF messages are unsized slices; a fixed array reborrows as one.
  fn msg_ref(m: &[u8; 32]) -> &Self::Msg {
    m
  }

  /// Aggregate the public keys via blst.
  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg = AggregatePublicKey::aggregate(pks, true).map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(agg.to_public_key())
  }

  /// Aggregate the signatures via blst.
  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg = AggregateSignature::aggregate(sigs, true).map_err(|_| BlsError::InvalidSignature)?;
    Ok(agg.to_signature())
  }

  /// Aggregate-verify one shared message against many keys.
  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: &Self::Msg, pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    verify_ok(sig.fast_aggregate_verify(true, msg, DST_BASIC, pks))
  }

  fn verify_aggregates(sig: &Self::InnerSig, msgs: &[&Self::Msg], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.len() != msgs.len() {
      return Err(BlsError::CountMismatch);
    }
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    // Two equal messages collapse to `e(H(m), pk_a + pk_b)`, proving only
    // that someone holds the sum. Absent a proof of possession, one signer
    // can pick `pk_b` to cancel `pk_a` and verify without them.
    let mut sorted: Vec<&[u8]> = msgs.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
      return Err(BlsError::DuplicateMessage);
    }
    verify_ok(sig.aggregate_verify(true, msgs, DST_BASIC, pks, true))
  }
}

impl BlsScIetf {
  /// The domain separation tag `id` signs and verifies under.
  const fn dst_of(id: BlsSigId) -> &'static [u8] {
    match id {
      BlsSigId::Basic => DST_BASIC,
      BlsSigId::ProofOfPossession => DST_POP,
    }
  }

  /// Sign under the DST selected by `id`.
  pub(crate) fn sign_with(sk: &SecretKey, msg: &[u8], id: BlsSigId) -> Signature {
    sk.sign(msg, Self::dst_of(id), &[])
  }

  /// Verify under the DST selected by `id`.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check does not hold.
  pub(crate) fn verify_with(sig: &Signature, msg: &[u8], pk: &PublicKey, id: BlsSigId) -> Result<(), BlsError> {
    verify_ok(sig.verify(true, msg, Self::dst_of(id), &[], pk, true))
  }

  /// Prove possession by signing the public key under the PoP-prove DST.
  pub(crate) fn prove_possession(sk: &SecretKey, pk: &PublicKey) -> Signature {
    sk.sign(&pk.compress(), DST_POP_PROVE, &[])
  }

  /// Verify a proof of possession under the PoP-prove DST.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the proof does not match the key.
  pub(crate) fn verify_possession(pk: &PublicKey, pop: &Signature) -> Result<(), BlsError> {
    verify_ok(pop.verify(true, &pk.compress(), DST_POP_PROVE, &[], pk, true))
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{MSG_DEADBEEF, RSEED};

  use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
  use hex_conservative::hex;
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct DhVector {
    sk: String,
    peer_pk: String,
    shared: String,
  }

  #[derive(Deserialize)]
  struct SignVector {
    sk: String,
    msg: String,
    sig: String,
  }

  #[test]
  fn dh_exchange_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_dh").scope("ietf");
    let vecs: Vec<DhVector> = corpus.vectors("dh");

    for v in &vecs {
      let sk = BlsScIetf::sk_from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let peer = BlsScIetf::pk_from_bytes(&arr_from_hex(&v.peer_pk)).unwrap();
      let shared = BlsScIetf::dh_exchange(&sk, &peer).unwrap();
      assert_eq!(BlsScIetf::pk_to_bytes(&shared).to_lower_hex_string(), v.shared);
    }
  }

  #[test]
  fn pyecc_signature_matches() {
    let sk = BlsScIetf::sk_from_bytes(&hex!(
      "0101010101010101010101010101010101010101010101010101010101010101"
    ))
    .unwrap();
    let msg = hex!("030104010509");
    let expected = hex!(concat!(
      "96ba34fac33c7f129d602a0bc8a3d43f9abc014eceaab7359146b4b150e57b808645738f35671e9e10e0d862a30cab70",
      "074eb5831d13e6a5b162d01eebe687d0164adbd0a864370a7c222a2768d7704da254f1bf1823665bc2361f9dd8c00e99"
    ));
    let sig = BlsScIetf::sign(&sk, &msg);
    assert_eq!(BlsScIetf::sig_to_bytes(&sig), expected);
    assert!(BlsScIetf::verify(&sig, &msg, &BlsScIetf::derive_pk(&sk)).is_ok());
  }

  #[test]
  fn signing_matches_vectors() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ietf_sign");
    let vecs: Vec<SignVector> = corpus.vectors("sign");

    for v in &vecs {
      let sk = BlsScIetf::sk_from_bytes(&arr_from_hex(&v.sk)).unwrap();
      let sig = BlsScIetf::sign(&sk, &vec_from_hex(&v.msg));
      assert_eq!(BlsScIetf::sig_to_bytes(&sig).to_lower_hex_string(), v.sig);
    }
  }

  #[test]
  fn signing_verifies_and_rejects_mismatches() {
    let sk0 = BlsScIetf::generate(&RSEED[0]).unwrap();
    let sk1 = BlsScIetf::generate(&RSEED[1]).unwrap();
    let pk0 = BlsScIetf::derive_pk(&sk0);
    let pk1 = BlsScIetf::derive_pk(&sk1);
    let sig = BlsScIetf::sign(&sk0, &MSG_DEADBEEF);

    assert!(BlsScIetf::verify(&sig, &MSG_DEADBEEF, &pk0).is_ok());
    assert!(BlsScIetf::verify(&sig, b"wrong", &pk0).is_err());
    assert!(BlsScIetf::verify(&sig, &MSG_DEADBEEF, &pk1).is_err());
    assert_eq!(BlsScIetf::sign(&sk0, &MSG_DEADBEEF), sig);
  }
}
