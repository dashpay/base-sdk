//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Thresholds for legacy scheme (m-of-n secret sharing and signature recovery).

use super::pk::PublicKey;
use super::sig::Signature;
use super::sk::SecretKey;
use crate::bls::blst_ffi::{G1, G2};
use crate::bls::scheme_ops as math;
use crate::bls::BlsError;
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

  /// Sign a 32-byte message, producing a signature share.
  pub fn sign(&self, msg: &[u8; 32]) -> SignatureShare {
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
/// ids.len()`; `InvalidShareId` if any id reduces to zero in the scalar
/// field; `DuplicateShareId` if any ids collide after reduction;
/// `InvalidSecretKey` if share generation or parsing fails.
pub fn split_sk(
  sk: &SecretKey,
  threshold: usize,
  ids: &[Hash256],
  rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<SecretKeyShare>, BlsError> {
  if threshold < 2 || ids.is_empty() || threshold > ids.len() {
    return Err(BlsError::ThresholdTooLarge);
  }

  // An id congruent to zero mod r would make the share equal the master key, and
  // ids congruent mod r collide during interpolation.
  let id_refs: Vec<&Hash256> = ids.iter().collect();
  math::reduce_share_ids(&id_refs)?;

  let sk_bytes = Zeroizing::new(sk.to_bytes());
  let raw =
    crate::bls::scheme_ops::generate_shares(&sk_bytes, threshold, ids, rng).map_err(|()| BlsError::InvalidSecretKey)?;

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
/// Returns `InsufficientShares` if fewer than 2 shares are provided,
/// `InvalidShareId` if any id reduces to zero in the scalar field, or
/// `DuplicateShareId` if any ids collide after reduction.
pub fn recover_sig(shares: &[&SignatureShare]) -> Result<Signature, BlsError> {
  if shares.len() < 2 {
    return Err(BlsError::InsufficientShares);
  }

  // Reduce and validate ids in the scalar field, rejecting zero-reducing
  // and (post-reduction) duplicate ids.
  let id_refs: Vec<&Hash256> = shares.iter().map(|s| &s.id).collect();
  let ids = math::reduce_share_ids(&id_refs)?;
  let points: Vec<G2> = shares.iter().map(|s| s.sig.0.to_projective()).collect();

  let recovered = math::interpolate_g2(&ids, &points);
  Ok(Signature::from_inner(recovered.to_affine()))
}

/// Derive a public key share by evaluating the master public
/// key polynomial at the given participant id.
///
/// # Errors
///
/// Returns `InvalidVerificationVector` if fewer than 2 master keys are
/// given, or `InvalidShareId` if `id` reduces to zero in the scalar field.
pub fn derive_pk_share(master_pks: &[&PublicKey], id: &Hash256) -> Result<PublicKey, BlsError> {
  // Evaluating the verification-vector polynomial needs >= 2 coefficients.
  if master_pks.len() < 2 {
    return Err(BlsError::InvalidVerificationVector);
  }
  let coeffs_g1: Vec<G1> = master_pks.iter().map(|pk| pk.0.to_projective()).collect();

  let x = math::reduce_id(id)?;
  let result = math::eval_poly_g1(&coeffs_g1, &x);

  Ok(PublicKey::from_inner(result.to_affine()))
}
