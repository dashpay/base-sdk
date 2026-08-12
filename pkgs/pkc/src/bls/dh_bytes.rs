//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS Diffie-Hellman shared key byte bag.

use crate::bls::BlsSchemeId;

use dash_types::derive_sbytes;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use core::marker::PhantomData;

/// Raw shared secret length (G1 compressed).
pub const BLS_DH_LEN: usize = 48;

/// A scheme-tagged Diffie-Hellman shared key, `sk * peer_pk`.
pub struct BlsDhBytes<S: BlsSchemeId> {
  inner: [u8; BLS_DH_LEN],
  _scheme: PhantomData<S>,
}

impl<S: BlsSchemeId> BlsDhBytes<S> {
  /// Wraps raw bytes.
  pub const fn from_bytes(bytes: [u8; BLS_DH_LEN]) -> Self {
    Self {
      inner: bytes,
      _scheme: PhantomData,
    }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_DH_LEN] {
    &self.inner
  }
}

impl<S: BlsSchemeId> Zeroize for BlsDhBytes<S> {
  fn zeroize(&mut self) {
    self.inner.zeroize();
  }
}

derive_sbytes!(for[S: BlsSchemeId] BlsDhBytes<S>, BLS_DH_LEN);

impl<S: BlsSchemeId> Clone for BlsDhBytes<S> {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner,
      _scheme: PhantomData,
    }
  }
}

impl<S: BlsSchemeId> Eq for BlsDhBytes<S> {}

impl<S: BlsSchemeId> PartialEq for BlsDhBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.inner.ct_eq(&other.inner).into()
  }
}
