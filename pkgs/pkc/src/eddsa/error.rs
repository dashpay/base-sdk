//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Errors types for Ed25519 operations.

use core::fmt;

/// Errors produced by Ed25519 operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EddsaError {
  /// public key bytes are not a usable curve point
  InvalidPublicKey,
  /// signature verification failed
  VerifyFailed,
}

impl fmt::Display for EddsaError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let text = match self {
      EddsaError::InvalidPublicKey => "public key bytes are not a usable curve point",
      EddsaError::VerifyFailed => "signature verification failed",
    };
    f.write_str(text)
  }
}

#[cfg(feature = "std")]
impl std::error::Error for EddsaError {}
