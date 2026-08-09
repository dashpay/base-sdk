//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS signature (96-byte compressed G2 point).

use super::pk::PublicKey;
use super::sk::Scheme;
use crate::bls::scheme_ietf::{DST_BASIC, DST_POP};
use crate::bls::scheme_ops::{verify_ok, BlsScheme};
use crate::bls::{BlsError, BlsScIetf, BlsSigBytes};

use blst::min_pk;
use dash_types::Unencodable;

/// A BLS signature (96-byte compressed G2 point).
#[derive(Clone, Debug, Eq, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "BlsSigBytes<BlsScIetf>", try_from = "BlsSigBytes<BlsScIetf>",)
)]
pub struct Signature(pub(super) min_pk::Signature);

impl Signature {
  pub(super) fn from_inner(inner: min_pk::Signature) -> Self {
    Self(inner)
  }

  /// Deserialize from 96 compressed bytes.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::InvalidSignature`] when the bytes are not a valid
  /// encoding or the point fails `validate` (identity or non-prime-order).
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
    BlsScIetf::sig_from_bytes(bytes).map(Self)
  }

  /// Serialize to 96 compressed bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    BlsScIetf::sig_to_bytes(&self.0)
  }

  /// Verify with the Basic scheme.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::VerifyFailed`] if the signature does not verify.
  pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<(), BlsError> {
    BlsScIetf::verify(&self.0, msg, &pk.0)
  }

  /// Verify with a specific scheme.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::VerifyFailed`] if the signature does not verify.
  pub fn verify_with(&self, msg: &[u8], pk: &PublicKey, scheme: Scheme) -> Result<(), BlsError> {
    let dst = match scheme {
      Scheme::Basic => DST_BASIC,
      Scheme::ProofOfPossession => DST_POP,
    };
    self.verify_raw(msg, pk, dst)
  }

  fn verify_raw(&self, msg: &[u8], pk: &PublicKey, dst: &[u8]) -> Result<(), BlsError> {
    verify_ok(self.0.verify(true, msg, dst, &[], &pk.0, true))
  }
}

crate::common::bls::impl_hash_via_bytes!(Signature);

impl From<Signature> for BlsSigBytes<BlsScIetf> {
  fn from(sig: Signature) -> Self {
    Self::from_bytes(sig.to_bytes())
  }
}

impl TryFrom<BlsSigBytes<BlsScIetf>> for Signature {
  type Error = BlsError;

  fn try_from(bytes: BlsSigBytes<BlsScIetf>) -> Result<Self, Self::Error> {
    Self::from_bytes(bytes.as_bytes())
  }
}
