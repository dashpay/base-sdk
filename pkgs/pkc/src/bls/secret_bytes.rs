//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS secret key byte bag.

use crate::bls::BlsSchemeId;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::codec::{Hashable, TypeId};
use dash_types::impl_sbytes;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt;
use core::marker::PhantomData;

/// Raw BLS secret key length (scalar).
pub const BLS_SK_LEN: usize = 32;

/// Scheme-tagged BLS secret key bytes (32 bytes, zeroized on drop).
pub struct BlsSkBytes<S: BlsSchemeId> {
  inner: [u8; BLS_SK_LEN],
  _scheme: PhantomData<S>,
}

impl_sbytes!(for[S: BlsSchemeId] BlsSkBytes<S>, BLS_SK_LEN);

impl<S: BlsSchemeId> Hashable for BlsSkBytes<S> {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_bytes(Sha256d::hash(&self.inner).to_byte_array())
  }
}

impl<S: BlsSchemeId> BlsSkBytes<S> {
  /// Wraps raw bytes.
  pub const fn from_bytes(bytes: [u8; BLS_SK_LEN]) -> Self {
    Self {
      inner: bytes,
      _scheme: PhantomData,
    }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_SK_LEN] {
    &self.inner
  }

  /// Copies out the inner bytes in a zeroizing wrapper.
  pub fn to_bytes(&self) -> Zeroizing<[u8; BLS_SK_LEN]> {
    Zeroizing::new(self.inner)
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.ct_eq(&[0u8; BLS_SK_LEN]).into()
  }
}

impl<S: BlsSchemeId> TypeId for BlsSkBytes<S> {
  const TYPE_ID: u32 = S::SK_TYPE_ID;
}

impl<S: BlsSchemeId> AsRef<[u8; BLS_SK_LEN]> for BlsSkBytes<S> {
  fn as_ref(&self) -> &[u8; BLS_SK_LEN] {
    &self.inner
  }
}

impl<S: BlsSchemeId> Clone for BlsSkBytes<S> {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner,
      _scheme: PhantomData,
    }
  }
}

impl<S: BlsSchemeId> Zeroize for BlsSkBytes<S> {
  fn zeroize(&mut self) {
    self.inner.zeroize();
  }
}

impl<S: BlsSchemeId> Drop for BlsSkBytes<S> {
  fn drop(&mut self) {
    <Self as Zeroize>::zeroize(self);
  }
}

impl<S: BlsSchemeId> ZeroizeOnDrop for BlsSkBytes<S> {}

impl<S: BlsSchemeId> Eq for BlsSkBytes<S> {}

impl<S: BlsSchemeId> PartialEq for BlsSkBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.inner.ct_eq(&other.inner).into()
  }
}

impl<S: BlsSchemeId> fmt::Debug for BlsSkBytes<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSkBytes<{}>(..)", S::LABEL)
  }
}

impl<S: BlsSchemeId> fmt::Display for BlsSkBytes<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Debug::fmt(self, f)
  }
}
