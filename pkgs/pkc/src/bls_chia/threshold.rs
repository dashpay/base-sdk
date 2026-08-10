//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Thresholds for legacy scheme (m-of-n secret sharing and signature recovery).

use super::{PublicKey, SecretKey, Signature};
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::{BlsError, BlsScChia};
use crate::prelude::*;

use dash_num::Hash256;
use dash_types::Unencodable;

use core::fmt;
use core::hash::{Hash, Hasher};

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

impl fmt::Debug for SecretKeyShare {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SecretKeyShare(id={:?})", self.id)
  }
}

/// Signature share from one threshold participant.
#[derive(Clone, Eq, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SignatureShare {
  id: Hash256,
  sig: Signature,
}

impl Hash for SignatureShare {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.id.hash(state);
    state.write(&self.sig.to_bytes());
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

impl fmt::Debug for SignatureShare {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SignatureShare(id={:?})", self.id)
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
  BlsScChia::split_sk(&sk.0, threshold, ids, rng, |id, inner| {
    SecretKeyShare::new(id, SecretKey::from_inner(inner))
  })
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
  let ids: Vec<_> = shares.iter().map(|s| &s.id).collect();
  let sigs: Vec<_> = shares.iter().map(|s| &s.sig.0).collect();
  BlsScChia::recover_sig_shares(&ids, &sigs).map(Signature::from_inner)
}

/// Derive a public key share by evaluating the master public
/// key polynomial at the given participant id.
///
/// # Errors
///
/// Returns `InvalidVerificationVector` if fewer than 2 master keys are
/// given, or `InvalidShareId` if `id` reduces to zero in the scalar field.
pub fn derive_pk_share(master_pks: &[&PublicKey], id: &Hash256) -> Result<PublicKey, BlsError> {
  let pks: Vec<_> = master_pks.iter().map(|pk| &pk.0).collect();
  BlsScChia::derive_pk_share(&pks, id).map(PublicKey::from_inner)
}
