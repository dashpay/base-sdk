//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold participant identifier.

use dash_types::derive_bytes;
use dash_types::type_id::Unencodable;

/// Threshold participant identifier length.
pub const BLS_ID_LEN: usize = 32;

/// Threshold participant identifier.
#[derive(Unencodable)]
pub struct BlsShareId {
  inner: [u8; BLS_ID_LEN],
}

impl BlsShareId {
  /// Wraps raw bytes.
  pub const fn from_bytes(bytes: [u8; BLS_ID_LEN]) -> Self {
    Self { inner: bytes }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_ID_LEN] {
    &self.inner
  }

  /// Returns the inner byte array.
  pub const fn into_bytes(self) -> [u8; BLS_ID_LEN] {
    self.inner
  }
}

derive_bytes!(BlsShareId, BLS_ID_LEN, rev);
