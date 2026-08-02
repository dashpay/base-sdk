//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS public key byte bag.

use crate::bls::BlsSchemeId;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::codec::{take, BaseCodec, DecodeError, EncodeBuf, Hashable, TypeId};
use dash_types::{derive_bytes, impl_type};

use core::fmt;
use core::marker::PhantomData;

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Scheme-tagged BLS public key bytes (48 bytes, unvalidated).
pub struct BlsPkBytes<S: BlsSchemeId> {
  inner: [u8; BLS_PK_LEN],
  _scheme: PhantomData<S>,
}

impl<S: BlsSchemeId> BaseCodec for BlsPkBytes<S> {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<BLS_PK_LEN>(data).map(Self::from_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.inner); // nosemgrep: codec-no-raw-extend
  }
}

impl_type!(for[S: BlsSchemeId] BlsPkBytes<S>, BLS_PK_LEN);

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

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.iter().all(|&b| b == 0)
  }
}

impl<S: BlsSchemeId> TypeId for BlsPkBytes<S> {
  const TYPE_ID: u32 = S::PK_TYPE_ID;
}

derive_bytes!(for[S: BlsSchemeId] BlsPkBytes<S>, BLS_PK_LEN);

impl<S: BlsSchemeId> fmt::Debug for BlsPkBytes<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "BlsPkBytes<{}>(", S::LABEL)?;
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
  }
}

impl<S: BlsSchemeId> fmt::Display for BlsPkBytes<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}
