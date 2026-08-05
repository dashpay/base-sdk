//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 signature.

use super::error::EcdsaError;
use super::sig_bytes::ECDSA_SIG_LEN;
use super::EcdsaSigBytes;

use dash_num::Hash256;
use dash_types::{dlgt_codec, type_cvrt, TypeId, Unencodable};
use k256::ecdsa::{DerSignature, Signature};

use core::hash::{Hash, Hasher};

/// An ECDSA signature (64-byte compact r||s).
#[derive(Clone, Debug, Eq, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "super::EcdsaSigBytes", try_from = "super::EcdsaSigBytes",)
)]
pub struct EcdsaSignature(Signature);

dlgt_codec!(EcdsaSignature => EcdsaSigBytes, Hash256, EcdsaError, ECDSA_SIG_LEN + 1);

impl EcdsaSignature {
  pub(super) fn from_inner(inner: Signature) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> &Signature {
    &self.0
  }

  /// Parse from 64-byte compact format (r || s).
  ///
  /// Accepts high-S signatures; see [`is_low_s`](Self::is_low_s) to reject
  /// otherwise.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidSignature`] when `r` or `s` is zero or not
  /// a scalar below the curve order.
  pub fn from_compact(bytes: &[u8; ECDSA_SIG_LEN]) -> Result<Self, EcdsaError> {
    Signature::from_slice(bytes)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSignature)
  }

  /// Parse from DER-encoded bytes.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::InvalidSignature`] when the DER framing is
  /// malformed or either scalar is out of range.
  pub fn from_der(bytes: &[u8]) -> Result<Self, EcdsaError> {
    Signature::from_der(bytes)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSignature)
  }

  /// Whether the S component is in the lower half of the curve order.
  pub fn is_low_s(&self) -> bool {
    self.0.normalize_s().is_none()
  }

  /// Return a signature with the S value normalised to the lower half of the
  /// curve order. Returns `None` if already normalised.
  pub fn normalize_s(&self) -> Option<Self> {
    self.0.normalize_s().map(Self)
  }

  /// Serialize as 64-byte compact format (r || s).
  pub fn to_compact(&self) -> [u8; ECDSA_SIG_LEN] {
    self.0.to_bytes().into()
  }

  /// Encode as DER bytes.
  pub fn to_der(&self) -> EcdsaDerSig {
    EcdsaDerSig(self.0.to_der())
  }
}

impl Hash for EcdsaSignature {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_compact().hash(state);
  }
}

impl AsRef<EcdsaSignature> for EcdsaSignature {
  fn as_ref(&self) -> &EcdsaSignature {
    self
  }
}

/// DER-encoded ECDSA signature (variable length, typically 70-72 bytes).
#[derive(Clone, Debug, Unencodable)]
pub struct EcdsaDerSig(DerSignature);

impl EcdsaDerSig {
  /// Raw DER bytes.
  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }

  /// Byte length.
  pub fn len(&self) -> usize {
    self.0.as_bytes().len()
  }

  /// Whether the DER encoding is empty (always false for valid signatures).
  pub fn is_empty(&self) -> bool {
    self.0.as_bytes().is_empty()
  }
}

impl Eq for EcdsaDerSig {}

impl Hash for EcdsaDerSig {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.as_bytes().hash(state);
  }
}

impl PartialEq for EcdsaDerSig {
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes() == other.as_bytes()
  }
}

type_cvrt!(From<EcdsaSignature> for EcdsaSigBytes, |sig| {
  Self::from(sig.to_compact())
});

type_cvrt!(TryFrom<EcdsaSigBytes> for EcdsaSignature, EcdsaError, |bytes| {
  Self::from_compact(bytes.as_bytes())
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{EcdsaPublicKey, EcdsaSigBytes, EcdsaSignature};

  #[cfg(feature = "serde")]
  use dash_dev::assert_json_rt;
  use rstest::*;

  #[rstest]
  fn compact_roundtrip(alice_sig: EcdsaSignature) {
    let bytes = alice_sig.to_compact();
    let restored = EcdsaSignature::from_compact(&bytes).unwrap();
    assert_eq!(restored, alice_sig);
  }

  #[rstest]
  fn bag_roundtrip(alice_sig: EcdsaSignature) {
    let bag = EcdsaSigBytes::from(&alice_sig);
    let restored = EcdsaSignature::try_from(bag).unwrap();
    assert_eq!(restored, alice_sig);
  }

  #[rstest]
  fn der_roundtrip(alice_sig: EcdsaSignature) {
    let der = alice_sig.to_der();
    let restored = EcdsaSignature::from_der(der.as_bytes()).unwrap();
    assert_eq!(restored, alice_sig);
  }

  #[rstest]
  fn der_bag_is_not_empty(alice_sig: EcdsaSignature) {
    let der = alice_sig.to_der();
    assert!(!der.is_empty());
    assert_eq!(der.len(), der.as_bytes().len());
  }

  #[rstest]
  fn is_low_s_after_signing(alice_sig: EcdsaSignature) {
    // Library already produces low-S signatures.
    assert!(alice_sig.is_low_s());
  }

  #[rstest]
  fn normalize_s_noop_when_already_low(alice_sig: EcdsaSignature) {
    assert!(alice_sig.normalize_s().is_none());
  }

  #[rstest]
  fn normalize_s_flips_high_s_signature(alice_pk: EcdsaPublicKey, alice_sig: EcdsaSignature) {
    let compact = alice_sig.to_compact();
    let mut high_bytes = [0u8; 64];
    high_bytes[..32].copy_from_slice(&compact[..32]);
    high_bytes[32..].copy_from_slice(&negate_scalar(&compact[32..]));
    let high_sig = EcdsaSignature::from_compact(&high_bytes).unwrap();
    assert!(!high_sig.is_low_s());

    let normalized = high_sig.normalize_s().unwrap();
    assert!(normalized.is_low_s());
    assert_eq!(normalized, alice_sig);
    assert!(alice_pk.verify(&MSG, &normalized).is_ok());
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_sig_roundtrip(alice_sig: EcdsaSignature) {
    assert_json_rt(&alice_sig);
  }
}
