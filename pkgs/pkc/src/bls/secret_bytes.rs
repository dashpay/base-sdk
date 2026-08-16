//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS secret key byte bag.

use crate::bls::BlsSchemeId;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::codec::Hashable;
use dash_types::type_id::TypeId;
use dash_types::{derive_sbytes, impl_sbytes};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

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
}

impl<S: BlsSchemeId> TypeId for BlsSkBytes<S> {
  const TYPE_ID: u32 = S::SK_TYPE_ID;
}

impl<S: BlsSchemeId> Zeroize for BlsSkBytes<S> {
  fn zeroize(&mut self) {
    self.inner.zeroize();
  }
}

derive_sbytes!(for[S: BlsSchemeId] BlsSkBytes<S>, BLS_SK_LEN);

impl<S: BlsSchemeId> Clone for BlsSkBytes<S> {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner,
      _scheme: PhantomData,
    }
  }
}

impl<S: BlsSchemeId> Eq for BlsSkBytes<S> {}

impl<S: BlsSchemeId> PartialEq for BlsSkBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.inner.ct_eq(&other.inner).into()
  }
}
