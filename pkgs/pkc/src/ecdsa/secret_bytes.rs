//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key byte bag.

use dash_types::{impl_sbyte, TypeId};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use core::fmt;

/// Raw ECDSA secret key bytes.
#[derive(Clone, Default, TypeId, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaSkBytes([u8; 32]);

impl_sbyte!(32, EcdsaSkBytes);

impl EcdsaSkBytes {
  /// Consumes the bag and returns the inner byte array.
  pub fn into_bytes(self) -> [u8; 32] {
    self.0
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0.ct_eq(&[0u8; 32]).into()
  }
}

impl Eq for EcdsaSkBytes {}

impl PartialEq for EcdsaSkBytes {
  fn eq(&self, other: &Self) -> bool {
    self.0.ct_eq(&other.0).into()
  }
}

impl AsRef<[u8]> for EcdsaSkBytes {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl AsRef<[u8; 32]> for EcdsaSkBytes {
  fn as_ref(&self) -> &[u8; 32] {
    &self.0
  }
}

impl fmt::Debug for EcdsaSkBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSkBytes(..)")
  }
}

impl fmt::Display for EcdsaSkBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Debug::fmt(self, f)
  }
}

impl From<EcdsaSkBytes> for [u8; 32] {
  fn from(val: EcdsaSkBytes) -> Self {
    val.0
  }
}
