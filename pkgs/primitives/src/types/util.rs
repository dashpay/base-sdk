//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Encoding helpers shared across address types.

use core::fmt::{self, Write as _};

/// RFC 4648 base32 alphabet (lowercase).
const CHARSET_B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes `data` as RFC 4648 Base32 without padding.
pub(super) fn base32r_enc(data: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
  let mut bits: u32 = 0;
  let mut n: u32 = 0;
  for &b in data {
    bits = (bits << 8) | u32::from(b);
    n += 8;
    while n >= 5 {
      n -= 5;
      let idx = ((bits >> n) & 0x1f) as usize;
      f.write_char(char::from(CHARSET_B32[idx]))?;
    }
  }
  if n > 0 {
    let idx = ((bits << (5 - n)) & 0x1f) as usize;
    f.write_char(char::from(CHARSET_B32[idx]))?;
  }
  Ok(())
}

/// Writes each byte as two lowercase hex digits.
pub(super) fn base16_enc(data: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
  for b in data {
    write!(f, "{b:02x}")?;
  }
  Ok(())
}
