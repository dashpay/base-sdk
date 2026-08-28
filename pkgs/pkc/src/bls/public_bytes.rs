//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS public key byte bag.

use crate::bls::BlsSchemeId;

#[cfg(feature = "codec")]
use bitcoin_hashes::sha256d::Hash as Sha256d;
#[cfg(feature = "codec")]
use dash_num::Hash256;
#[cfg(feature = "codec")]
use dash_types::codec::Hashable;
use dash_types::derive_bytes;
#[cfg(feature = "codec")]
use dash_types::impl_bytes;
#[cfg(feature = "codec")]
use dash_types::type_id::TypeId;

use core::marker::PhantomData;

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Scheme-tagged BLS public key bytes (48 bytes, unvalidated).
#[cfg_attr(feature = "codec", derive(TypeId))]
pub struct BlsPkBytes<S: BlsSchemeId> {
  inner: [u8; BLS_PK_LEN],
  _scheme: PhantomData<S>,
}

#[cfg(feature = "codec")]
impl_bytes!(for[S: BlsSchemeId] BlsPkBytes<S>, BLS_PK_LEN);

#[cfg(feature = "codec")]
impl<S: BlsSchemeId> Hashable for BlsPkBytes<S> {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_bytes(Sha256d::hash(&self.inner).to_byte_array())
  }
}

impl<S: BlsSchemeId> BlsPkBytes<S> {
  /// Wraps raw bytes.
  pub const fn from_bytes(bytes: [u8; BLS_PK_LEN]) -> Self {
    Self {
      inner: bytes,
      _scheme: PhantomData,
    }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_PK_LEN] {
    &self.inner
  }

  /// Returns the inner byte array.
  pub const fn into_bytes(self) -> [u8; BLS_PK_LEN] {
    self.inner
  }
}

derive_bytes!(for[S: BlsSchemeId] BlsPkBytes<S>, BLS_PK_LEN);
