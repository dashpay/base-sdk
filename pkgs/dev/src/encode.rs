//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Encoding/decoding logic.

use crate::prelude::*;

use hex_conservative::FromHex;

/// Decodes a base-16 string into a fixed `N`-byte array.
///
/// # Panics
///
/// Panics on a non-hex digit or unless the input decodes to exactly `N` bytes.
pub fn arr_from_hex<const N: usize>(s: &str) -> [u8; N] {
  <[u8; N]>::from_hex(s).unwrap_or_else(|e| panic!("bad hex: {e}"))
}

/// Decodes a base-16 string into a byte vector.
///
/// # Panics
///
/// Panics if `s` has odd length or contains a non-hex digit.
pub fn vec_from_hex(s: &str) -> Vec<u8> {
  Vec::<u8>::from_hex(s).unwrap_or_else(|e| panic!("bad hex: {e}"))
}
