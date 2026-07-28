//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Basic BLS scheme implementation.

use super::blst_ffi::{self, G1Affine, G2Affine, Point, G1};
use super::error::BlsError;
use super::scheme_ops::{self, BlsScheme};
use super::schemes::BlsScIetf;
use crate::bls_ietf::DST_BASIC;
use crate::prelude::*;

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use dash_num::Hash256;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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

  /// Multiply the peer public key by the secret scalar.
  fn dh_exchange(sk: &Self::InnerSk, peer_pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError> {
    let compressed = peer_pk.compress();
    let aff = G1Affine::uncompress(&compressed).map_err(|_| BlsError::InvalidPublicKey)?;
    let mut sk_bytes = sk.to_bytes();
    let mut sk_scalar = blst_ffi::scalar_from_bendian(&sk_bytes);
    let out_bytes = aff.mul_scalar(&sk_scalar.b, blst_ffi::FR_BITS).compress();
    sk_bytes.zeroize();
    sk_scalar.b.zeroize();
    Self::pk_from_bytes(&out_bytes)
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

  /// Hash-weight each key before summing, then verify (rogue-key safe).
  fn secure_verify_aggregates(sig: &Self::InnerSig, msg: &Self::Msg, pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    let mut sorted: Vec<[u8; 48]> = pks.iter().map(|pk| Self::pk_to_bytes(pk)).collect();
    sorted.sort();

    let mut hasher = Sha256::new();
    for pk_bytes in &sorted {
      hasher.update(pk_bytes);
    }
    let pk_hash: [u8; 32] = hasher.finalize().into();

    let mut acc = G1::identity();

    for (i, pk_bytes) in sorted.iter().enumerate() {
      // weight = SHA256(i_as_4_bytes_be || pk_hash) mod order
      let mut weight_hasher = Sha256::new();
      let idx_bytes = (i as u32).to_be_bytes();
      weight_hasher.update(idx_bytes);
      weight_hasher.update(pk_hash);
      let weight_hash: [u8; 32] = weight_hasher.finalize().into();

      // blst_p1_mult reduces internally.
      let weight = blst_ffi::scalar_from_bendian(&weight_hash);

      let pk_aff = G1Affine::uncompress(pk_bytes).map_err(|_| BlsError::InvalidPublicKey)?;
      acc = acc + pk_aff.to_projective().mul_scalar(&weight.b, 256);
    }

    let agg_pk_bytes = acc.to_affine().compress();
    let agg_pk = Self::pk_from_bytes(&agg_pk_bytes).map_err(|_| BlsError::InvalidPublicKey)?;

    Self::verify(sig, msg, &agg_pk)
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

  /// Evaluate the master verification-vector polynomial in G1 at `id`.
  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &Hash256) -> Result<Self::InnerPk, BlsError> {
    // Evaluating the verification-vector polynomial needs >= 2 coefficients.
    if master_pks.len() < 2 {
      return Err(BlsError::InvalidVerificationVector);
    }
    // Convert each PublicKey to G1 via G1Affine.
    let coeffs_g1 = master_pks
      .iter()
      .map(|pk| {
        let bytes = Self::pk_to_bytes(pk);
        let aff = G1Affine::uncompress(&bytes).map_err(|_| BlsError::InvalidPublicKey)?;
        Ok(aff.to_projective())
      })
      .collect::<Result<Vec<_>, BlsError>>()?;

    let x = scheme_ops::reduce_id(id)?;
    let result = scheme_ops::eval_poly_g1(&coeffs_g1, &x);

    let bytes = result.to_affine().compress();
    Self::pk_from_bytes(&bytes)
  }
}
