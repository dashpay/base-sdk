//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ECDSA signature and recovery id.

use k256::ecdsa;

use super::error::Error;

/// An ECDSA signature (64-byte compact r||s).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(ecdsa::Signature);

impl Signature {
  pub(super) fn from_inner(inner: ecdsa::Signature) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> &ecdsa::Signature {
    &self.0
  }

  /// Parse from 64-byte compact format (r || s).
  pub fn from_compact(bytes: &[u8; 64]) -> Result<Self, Error> {
    ecdsa::Signature::from_slice(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidSignature)
  }

  /// Parse from DER-encoded bytes.
  pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
    ecdsa::Signature::from_der(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidSignature)
  }

  /// Serialize as 64-byte compact format (r || s).
  pub fn to_compact(&self) -> [u8; 64] {
    self.0.to_bytes().into()
  }

  /// Encode as DER.
  pub fn to_der(&self) -> DerSignature {
    DerSignature(self.0.to_der())
  }
}

impl core::hash::Hash for Signature {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.to_compact().hash(state);
  }
}

/// Recovery id (0..3) used to recover a public key from an ECDSA signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RecoveryId(ecdsa::RecoveryId);

impl RecoveryId {
  pub(super) fn from_inner(inner: ecdsa::RecoveryId) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> ecdsa::RecoveryId {
    self.0
  }

  /// Create from a raw byte (0, 1, 2, or 3).
  pub fn new(id: u8) -> Result<Self, Error> {
    ecdsa::RecoveryId::try_from(id)
      .map(Self)
      .map_err(|_| Error::InvalidRecoveryId)
  }

  /// Return the raw byte value.
  pub fn to_byte(self) -> u8 {
    self.0.to_byte()
  }
}

/// DER-encoded ECDSA signature (variable length, typically 70-72 bytes).
#[derive(Clone, Debug)]
pub struct DerSignature(ecdsa::DerSignature);

impl DerSignature {
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

impl PartialEq for DerSignature {
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes() == other.as_bytes()
  }
}

impl Eq for DerSignature {}

#[cfg(feature = "serde")]
mod serde_impl {
  use super::*;
  use serde::{Deserialize, Deserializer, Serialize, Serializer};

  impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      serde::Serialize::serialize(&self.to_compact().as_slice(), s)
    }
  }

  impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
      let v = <alloc::vec::Vec<u8>>::deserialize(d)?;
      let bytes: [u8; 64] = v
        .try_into()
        .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
      Signature::from_compact(&bytes).map_err(serde::de::Error::custom)
    }
  }

  impl Serialize for RecoveryId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
      serde::Serialize::serialize(&self.to_byte(), s)
    }
  }

  impl<'de> Deserialize<'de> for RecoveryId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
      let byte = u8::deserialize(d)?;
      RecoveryId::new(byte).map_err(serde::de::Error::custom)
    }
  }
}
