//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signature (96-byte G2 point, legacy serialization).

use super::pk::PublicKey;
use crate::bls::blst_ffi::G2Affine;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::{BlsError, BlsScChia};

use dash_types::Unencodable;

/// A legacy BLS signature (96-byte G2 point in legacy serialization).
#[derive(Clone, Debug, Eq, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "crate::BlsSignatureBytes", try_from = "crate::BlsSignatureBytes",)
)]
pub struct Signature(pub(super) G2Affine);

impl Signature {
  pub(super) fn from_inner(inner: G2Affine) -> Self {
    Self(inner)
  }

  /// Deserialize from 96 legacy-format bytes.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
    BlsScChia::sig_from_bytes(bytes).map(Self)
  }

  /// Serialize to 96 legacy-format bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    BlsScChia::sig_to_bytes(&self.0)
  }

  /// Verify against a 32-byte message and public key via pairing check:
  /// e(sig, G1) == e(H(msg), pk).
  pub fn verify(&self, msg: &[u8; 32], pk: &PublicKey) -> Result<(), BlsError> {
    BlsScChia::verify(&self.0, msg, &pk.0)
  }
}

crate::common::bls::impl_hash_via_bytes!(Signature);

impl From<Signature> for crate::BlsSignatureBytes {
  fn from(sig: Signature) -> Self {
    Self(sig.to_bytes())
  }
}

impl TryFrom<crate::BlsSignatureBytes> for Signature {
  type Error = crate::bls::BlsError;

  fn try_from(bytes: crate::BlsSignatureBytes) -> Result<Self, Self::Error> {
    Self::from_bytes(&bytes.0)
  }
}
