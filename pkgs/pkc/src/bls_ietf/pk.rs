//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS public key (48-byte compressed G1 point).

use super::sig::Signature;
use super::sk::SecretKey;
use crate::bls::scheme_ietf::DST_POP_PROVE;
use crate::bls::scheme_ops::{verify_ok, BlsScheme};
use crate::bls::{BlsError, BlsPkBytes, BlsScIetf};

use blst::min_pk;
use dash_types::Unencodable;

/// A BLS public key (48-byte compressed G1 point).
#[derive(Clone, Debug, Eq, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "BlsPkBytes<BlsScIetf>", try_from = "BlsPkBytes<BlsScIetf>",)
)]
pub struct PublicKey(pub(super) min_pk::PublicKey);

impl PublicKey {
  pub(super) fn from_inner(inner: min_pk::PublicKey) -> Self {
    Self(inner)
  }

  /// Deserialize from 48 compressed bytes.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::InvalidPublicKey`] when the bytes are not a valid
  /// encoding or the point fails `validate` (identity or non-prime-order).
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
    BlsScIetf::pk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 48 compressed bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    BlsScIetf::pk_to_bytes(&self.0)
  }

  /// Compute a DH shared key: `sk * peer_pk`.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::InvalidPublicKey`] when `peer_pk` or the resulting
  /// point is not a valid public key.
  pub fn dh_exchange(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Self, BlsError> {
    BlsScIetf::dh_exchange(&sk.0, &peer_pk.0).map(Self)
  }

  /// Verify a proof of possession against this key.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::VerifyFailed`] if the proof does not verify.
  pub fn verify_possession(&self, pop: &Signature) -> Result<(), BlsError> {
    let pk_bytes = self.to_bytes();
    verify_ok(pop.0.verify(true, &pk_bytes, DST_POP_PROVE, &[], &self.0, true))
  }
}

crate::common::bls::impl_hash_via_bytes!(PublicKey);

impl From<PublicKey> for BlsPkBytes<BlsScIetf> {
  fn from(pk: PublicKey) -> Self {
    Self::from_bytes(pk.to_bytes())
  }
}

impl TryFrom<BlsPkBytes<BlsScIetf>> for PublicKey {
  type Error = BlsError;

  fn try_from(bytes: BlsPkBytes<BlsScIetf>) -> Result<Self, Self::Error> {
    Self::from_bytes(bytes.as_bytes())
  }
}
