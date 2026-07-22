//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Basic BLS scheme implementation.

use super::blst_ffi::{G1Affine, G2Affine, G1};
use super::error::BlsError;
use super::scheme_ops::{self, BlsScheme};
use super::schemes::BlsScIetf;
use crate::bls_ietf::DST_BASIC;
use crate::prelude::*;

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use dash_num::Hash256;

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

  /// No-op; `blst` zeroizes the key on drop.
  fn zeroize_sk(_sk: &mut Self::InnerSk) {
    // blst::min_pk::SecretKey zeroizes on drop internally.
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

  /// Sign with the basic-scheme DST.
  fn sign(sk: &Self::InnerSk, msg: &Self::Msg) -> Self::InnerSig {
    sk.sign(msg, DST_BASIC, &[])
  }

  /// Verify against the basic-scheme DST.
  fn verify(sig: &Self::InnerSig, msg: &Self::Msg, pk: &Self::InnerPk) -> Result<(), BlsError> {
    let result = sig.verify(true, msg, DST_BASIC, &[], pk, true);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
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
    let result = sig.fast_aggregate_verify(true, msg, DST_BASIC, pks);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  /// Lagrange-interpolate the share signatures in G2 at x=0.
  fn recover_sig_shares(ids: &[&Hash256], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.len() < 2 {
      return Err(BlsError::InsufficientShares);
    }

    // Reduce and validate ids in the scalar field, rejecting zero-reducing
    // and (post-reduction) duplicate ids.
    let reduced = scheme_ops::reduce_share_ids(ids)?;

    // Convert Signature -> compressed bytes -> G2Affine -> G2.
    let points = sigs
      .iter()
      .map(|s| {
        let bytes = Self::sig_to_bytes(s);
        let aff = G2Affine::uncompress(&bytes).map_err(|_| BlsError::InvalidSignature)?;
        Ok(aff.to_projective())
      })
      .collect::<Result<Vec<_>, BlsError>>()?;

    let recovered = scheme_ops::interpolate_g2(&reduced, &points);

    // Convert back: G2 -> G2Affine -> compressed bytes -> Signature.
    let bytes = recovered.to_affine().compress();
    Self::sig_from_bytes(&bytes).map_err(|_| BlsError::InvalidSignature)
  }
}

#[cfg(all(test, feature = "tests"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{MSG_DEADBEEF, SEED_0, SEED_1};
  use crate::prelude::*;

  use dash_dev::{arr_from_hex, vec_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use hex_literal::hex;
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
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_ietf_dh");
    let vecs: Vec<DhVector> = corpus.vectors("dh_exchange");

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
      "0101010101010101010101010101010101"
      "010101010101010101010101010101"
    ))
    .unwrap();
    let msg = hex!("030104010509");
    let expected = hex!(
      "96ba34fac33c7f129d602a0bc8a3d43f"
      "9abc014eceaab7359146b4b150e57b80"
      "8645738f35671e9e10e0d862a30cab70"
      "074eb5831d13e6a5b162d01eebe687d0"
      "164adbd0a864370a7c222a2768d7704d"
      "a254f1bf1823665bc2361f9dd8c00e99"
    );
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
    let sk0 = BlsScIetf::generate(&SEED_0).unwrap();
    let sk1 = BlsScIetf::generate(&SEED_1).unwrap();
    let pk0 = BlsScIetf::derive_pk(&sk0);
    let pk1 = BlsScIetf::derive_pk(&sk1);
    let sig = BlsScIetf::sign(&sk0, &MSG_DEADBEEF);

    assert!(BlsScIetf::verify(&sig, &MSG_DEADBEEF, &pk0).is_ok());
    assert!(BlsScIetf::verify(&sig, b"wrong", &pk0).is_err());
    assert!(BlsScIetf::verify(&sig, &MSG_DEADBEEF, &pk1).is_err());
    assert_eq!(BlsScIetf::sign(&sk0, &MSG_DEADBEEF), sig);
  }
}
