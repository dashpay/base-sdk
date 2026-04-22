//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hex parsing error type.

use core::fmt;

/// Error returned when parsing a hex string fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseHexError {
  /// The hex string has an odd number of characters.
  OddLength,
  /// The decoded byte count does not match the expected length.
  InvalidLength { expected: usize, got: usize },
  /// A non-hex character was encountered.
  InvalidChar(u8),
}

impl fmt::Display for ParseHexError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::OddLength => write!(f, "hex string has odd length"),
      Self::InvalidLength { expected, got } => {
        write!(f, "expected {expected} hex chars, got {got}")
      }
      Self::InvalidChar(c) => {
        write!(f, "invalid hex character: {:#04x}", c)
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseHexError {}
