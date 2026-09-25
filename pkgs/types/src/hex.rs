//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hex parsing and rendering.

use hex_conservative::{BytesToHexIter, Case};

use core::fmt::{self, Write as _};

/// Error returned when parsing a hex string fails.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseHexError {
  /// The hex string has an odd number of characters.
  OddLength,
  /// The hex character count does not match the expected length.
  InvalidLength {
    /// Hex characters the target type accepts, twice its byte width.
    expected: usize,
    /// Hex characters supplied, after any prefix was stripped.
    got: usize,
  },
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

impl core::error::Error for ParseHexError {}

/// Writes little-endian storage as big-endian hex, honouring `{:#x}`.
///
/// # Errors
///
/// Returns an error when the formatter does.
pub fn write_hex(bytes: &[u8], case: Case, f: &mut fmt::Formatter<'_>) -> fmt::Result {
  if f.alternate() {
    f.write_str(if case == Case::Lower { "0x" } else { "0X" })?;
  }
  for [hi, lo] in BytesToHexIter::new(bytes.iter().rev().copied(), case) {
    f.write_char(char::from(hi))?;
    f.write_char(char::from(lo))?;
  }
  Ok(())
}
