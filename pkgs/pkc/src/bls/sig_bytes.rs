//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS signature byte bag.

use crate::bls::BlsSchemeId;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::codec::{Hashable, TypeId};
use dash_types::{derive_bytes, impl_bytes};

use core::fmt;
use core::marker::PhantomData;

/// Raw BLS signature length (G2 compressed).
pub const BLS_SIG_LEN: usize = 96;

/// Scheme-tagged BLS signature bytes (96 bytes, unvalidated).
pub struct BlsSigBytes<S: BlsSchemeId> {
  inner: [u8; BLS_SIG_LEN],
  _scheme: PhantomData<S>,
}

impl_bytes!(for[S: BlsSchemeId] BlsSigBytes<S>, BLS_SIG_LEN);

impl<S: BlsSchemeId> Hashable for BlsSigBytes<S> {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_bytes(Sha256d::hash(&self.inner).to_byte_array())
  }
}

impl<S: BlsSchemeId> BlsSigBytes<S> {
  /// Wraps raw bytes.
  pub const fn from_bytes(bytes: [u8; BLS_SIG_LEN]) -> Self {
    Self {
      inner: bytes,
      _scheme: PhantomData,
    }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_SIG_LEN] {
    &self.inner
  }

  /// Returns the inner byte array.
  pub const fn into_bytes(self) -> [u8; BLS_SIG_LEN] {
    self.inner
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.iter().all(|&b| b == 0)
  }
}

impl<S: BlsSchemeId> TypeId for BlsSigBytes<S> {
  const TYPE_ID: u32 = S::SIG_TYPE_ID;
}

derive_bytes!(for[S: BlsSchemeId] BlsSigBytes<S>, BLS_SIG_LEN);

impl<S: BlsSchemeId> fmt::Debug for BlsSigBytes<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSigBytes<{}>(", S::LABEL)?;
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
  }
}

impl<S: BlsSchemeId> fmt::Display for BlsSigBytes<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}
