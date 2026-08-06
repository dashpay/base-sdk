//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS public key (48-byte G1 point, legacy serialization).

use crate::bls::blst_ffi::G1Affine;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::{BlsError, BlsPkBytes, BlsScChia};

use dash_types::Unencodable;

/// A legacy BLS public key (48-byte G1 point in legacy serialization).
#[derive(Clone, Debug, Eq, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "BlsPkBytes<BlsScChia>", try_from = "BlsPkBytes<BlsScChia>",)
)]
pub struct PublicKey(pub(super) G1Affine);

impl PublicKey {
  pub(super) fn from_inner(inner: G1Affine) -> Self {
    Self(inner)
  }

  /// Deserialize from 48 legacy-format bytes.
  ///
  /// # Errors
  ///
  /// Returns [`BlsError::InvalidPublicKey`] when the bytes do not decode to a
  /// valid public key (identity marker, all-zero buffer, or malformed input).
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
    BlsScChia::pk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 48 legacy-format bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    BlsScChia::pk_to_bytes(&self.0)
  }
}

crate::common::bls::impl_hash_via_bytes!(PublicKey);

impl From<PublicKey> for BlsPkBytes<BlsScChia> {
  fn from(pk: PublicKey) -> Self {
    Self::from_bytes(pk.to_bytes())
  }
}

impl TryFrom<BlsPkBytes<BlsScChia>> for PublicKey {
  type Error = BlsError;

  fn try_from(bytes: BlsPkBytes<BlsScChia>) -> Result<Self, Self::Error> {
    Self::from_bytes(bytes.as_bytes())
  }
}
