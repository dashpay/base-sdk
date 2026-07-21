//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Thresholds for IETF scheme (m-of-n secret sharing and signature recovery).

use super::pk::PublicKey;
use super::sig::Signature;
use super::sk::SecretKey;
use crate::bls::blst_ffi::{Fr, G1Affine, G2Affine, G1, G2};
use crate::bls::BlsError;
use crate::common::bls::threshold as math;
use crate::prelude::*;

use dash_num::Hash256;
use zeroize::Zeroizing;

/// Secret key share for threshold signing.
#[derive(Clone)]
pub struct SecretKeyShare {
  id: Hash256,
  sk: SecretKey,
}

impl SecretKeyShare {
  /// Construct a secret key share from an ID and a secret key.
  pub fn new(id: Hash256, sk: SecretKey) -> Self {
    Self { id, sk }
  }

  /// Participant identifier (32-byte hash).
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// Sign a message, producing a signature share.
  pub fn sign(&self, msg: &[u8]) -> SignatureShare {
    SignatureShare {
      id: self.id,
      sig: self.sk.sign(msg),
    }
  }

  /// The underlying secret key.
  pub fn secret_key(&self) -> &SecretKey {
    &self.sk
  }
}

impl core::fmt::Debug for SecretKeyShare {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "SecretKeyShare(id={:?})", self.id)
  }
}

/// Signature share from one threshold participant.
#[derive(Clone)]
pub struct SignatureShare {
  id: Hash256,
  sig: Signature,
}

impl core::fmt::Debug for SignatureShare {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "SignatureShare(id={:?})", self.id)
  }
}

impl SignatureShare {
  /// Construct a signature share from an ID and a signature.
  pub fn new(id: Hash256, sig: Signature) -> Self {
    Self { id, sig }
  }

  /// Participant identifier (32-byte hash).
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// The underlying signature.
  pub fn signature(&self) -> &Signature {
    &self.sig
  }
}

/// Split a secret key into shares for the given participant IDs, requiring
/// `threshold` shares to recover.
///
/// # Errors
///
/// Returns `ThresholdTooLarge` if `threshold < 2` (a 1-of-n split hands
/// the master key to every participant), `ids` is empty, or `threshold >
/// ids.len()`.
pub fn split_sk(
  sk: &SecretKey,
  threshold: usize,
  ids: &[Hash256],
  rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<SecretKeyShare>, BlsError> {
  if threshold < 2 || ids.is_empty() || threshold > ids.len() {
    return Err(BlsError::ThresholdTooLarge);
  }

  // Reject zero IDs.
  for id in ids {
    if id.is_null() {
      return Err(BlsError::ThresholdTooLarge);
    }
  }

  // Reject duplicate IDs.
  for i in 0..ids.len() {
    for j in (i + 1)..ids.len() {
      if ids[i] == ids[j] {
        return Err(BlsError::DuplicateShareId);
      }
    }
  }

  let sk_bytes = Zeroizing::new(sk.to_bytes());
  let raw =
    crate::common::bls::generate_shares(&sk_bytes, threshold, ids, rng).map_err(|()| BlsError::InvalidSecretKey)?;

  raw
    .into_iter()
    .map(|share| {
      let share_sk = SecretKey::from_bytes(&share.secret).map_err(|_| BlsError::InvalidSecretKey)?;
      Ok(SecretKeyShare {
        id: share.id,
        sk: share_sk,
      })
    })
    .collect()
}

/// Recover a full signature from threshold signature shares via Lagrange
/// interpolation in G2.
///
/// # Errors
///
/// Returns `InsufficientShares` if fewer than 2 shares are provided, or
/// `DuplicateShareId` if any ids repeat.
pub fn recover_sig(shares: &[&SignatureShare]) -> Result<Signature, BlsError> {
  if shares.len() < 2 {
    return Err(BlsError::InsufficientShares);
  }

  // Check for duplicate IDs
  for i in 0..shares.len() {
    for j in (i + 1)..shares.len() {
      if shares[i].id == shares[j].id {
        return Err(BlsError::DuplicateShareId);
      }
    }
  }

  let ids: Vec<Fr> = shares.iter().map(|s| math::fr_from_hash(&s.id)).collect();

  // Convert min_pk::Signature -> compressed bytes -> G2Affine -> G2.
  let points: Vec<G2> = shares
    .iter()
    .map(|s| {
      let bytes = s.sig.to_bytes();
      let aff = G2Affine::uncompress(&bytes).map_err(|_| BlsError::InvalidSignature)?;
      Ok(aff.to_projective())
    })
    .collect::<Result<Vec<_>, BlsError>>()?;

  let recovered = math::interpolate_g2(&ids, &points);

  // Convert back: G2 -> G2Affine -> compressed bytes -> min_pk::Signature.
  let bytes = recovered.to_affine().compress();
  Signature::from_bytes(&bytes).map_err(|_| BlsError::InvalidSignature)
}

/// Derive a public key share by evaluating the master public
/// key polynomial at the given participant id.
pub fn derive_pk_share(master_pks: &[&PublicKey], id: &Hash256) -> Result<PublicKey, BlsError> {
  if master_pks.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  // Convert each min_pk::PublicKey to G1 via G1Affine.
  let coeffs_g1: Vec<G1> = master_pks
    .iter()
    .map(|pk| {
      let bytes = pk.0.compress();
      let aff = G1Affine::uncompress(&bytes).map_err(|_| BlsError::InvalidPublicKey)?;
      Ok(aff.to_projective())
    })
    .collect::<Result<Vec<_>, BlsError>>()?;

  let x = math::fr_from_hash(id);
  let result = math::eval_poly_g1(&coeffs_g1, &x);

  let bytes = result.to_affine().compress();
  PublicKey::from_bytes(&bytes)
}
