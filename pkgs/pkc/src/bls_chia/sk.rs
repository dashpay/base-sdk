//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS secret key.

use super::pk::PublicKey;
use super::sig::Signature;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::{BlsError, BlsScChia};

use core::fmt;

/// A legacy BLS secret key (32-byte scalar).
#[derive(Clone)]
pub struct SecretKey(pub(super) blst::blst_scalar);

impl SecretKey {
  pub(super) fn from_inner(inner: blst::blst_scalar) -> Self {
    Self(inner)
  }

  /// Derive a secret key from input keying material (>= 32 bytes). Uses the
  /// same IETF key generation as standard BLS, only the signing scheme
  /// differs.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when `ikm` is shorter than 32 bytes or the
  /// derived scalar is not a valid secret key.
  pub fn generate(ikm: &[u8]) -> Result<Self, BlsError> {
    BlsScChia::generate(ikm).map(Self)
  }

  /// Parse from 32-byte big-endian scalar.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when the scalar is zero or not less than the
  /// group order.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
    BlsScChia::sk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 32 bytes.
  pub fn to_bytes(&self) -> [u8; 32] {
    BlsScChia::sk_to_bytes(&self.0)
  }

  /// Derive the corresponding public key (G1 point).
  pub fn public_key(&self) -> PublicKey {
    PublicKey::from_inner(BlsScChia::derive_pk(&self.0))
  }

  /// Sign a 32-byte message hash using the legacy scheme (no DST, Shallue-van
  /// de Woestijne hash-to-G2).
  pub fn sign(&self, msg: &[u8; 32]) -> Signature {
    Signature::from_inner(BlsScChia::sign(&self.0, msg))
  }
}

impl Drop for SecretKey {
  fn drop(&mut self) {
    BlsScChia::zeroize_sk(&mut self.0);
  }
}

impl fmt::Debug for SecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SecretKey(..)")
  }
}
