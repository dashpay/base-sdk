//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compact difficulty target encoding.

use crate::Arith256;

#[cfg(feature = "codec")]
use dash_types::impl_num;
use dash_types::{Numeric, ParseHexError};

use core::fmt;
use core::str::FromStr;

/// Compact difficulty target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompactTarget(u32);

/// Result of decoding a compact difficulty target.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DecodedTarget {
  /// The decoded 256-bit target value.
  pub value: Arith256,
  /// Whether the sign bit was set in the mantissa.
  pub negative: bool,
  /// Whether the encoded exponent exceeds the valid range.
  pub overflow: bool,
}

impl Numeric for CompactTarget {
  type Base = u32;

  type Bytes = [u8; 4];

  const ZERO: Self = Self(0);

  fn from_base(v: u32) -> Self {
    Self(v)
  }

  fn to_base(&self) -> u32 {
    self.0
  }

  fn from_lendian(bytes: [u8; 4]) -> Self {
    Self::from_base(u32::from_lendian(bytes))
  }

  fn to_lendian(&self) -> [u8; 4] {
    self.0.to_lendian()
  }

  fn from_bendian(bytes: [u8; 4]) -> Self {
    Self::from_base(u32::from_bendian(bytes))
  }

  fn to_bendian(&self) -> [u8; 4] {
    self.0.to_bendian()
  }
}

#[cfg(feature = "codec")]
impl_num!(CompactTarget, u32);

impl CompactTarget {
  /// Wraps a raw `nBits` word.
  #[inline]
  pub fn new(bits: u32) -> Self {
    Self(bits)
  }

  /// Expand this compact (nBits) representation to a 256-bit target value.
  pub fn expand(self) -> DecodedTarget {
    let compact = self.0;
    let size = (compact >> 24) as usize;
    let mut word = compact & 0x007f_ffff;

    let value = if size <= 3 {
      word >>= 8 * (3 - size);
      Arith256::from_u64(word as u64)
    } else {
      let v = Arith256::from_u64(word as u64);
      v.wrapping_shl((8 * (size - 3)) as u32)
    };

    let negative = word != 0 && (compact & 0x0080_0000) != 0;
    let overflow = word != 0 && ((size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32));

    DecodedTarget {
      value,
      negative,
      overflow,
    }
  }
}

impl fmt::Display for CompactTarget {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:#010x}", self.0)
  }
}

/// Parses the `0x`-prefixed hex rendered by [`Display`](fmt::Display).
impl FromStr for CompactTarget {
  type Err = ParseHexError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

    if digits.is_empty() || digits.len() > 8 {
      return Err(ParseHexError::InvalidLength {
        expected: 8,
        got: digits.len(),
      });
    }

    let mut bits: u32 = 0;
    for b in digits.bytes() {
      let digit = match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => return Err(ParseHexError::InvalidChar(b)),
      };
      bits = (bits << 4) | u32::from(digit);
    }

    Ok(Self(bits))
  }
}

impl Arith256 {
  /// Compact this value to its `nBits` representation.
  pub fn compact(self, negative: bool) -> CompactTarget {
    let mut size = self.bits().div_ceil(8);
    let mut compact: u32 = if size <= 3 {
      (self.low_u64() << (8 * (3 - size as u64))) as u32
    } else {
      let bn = self.wrapping_shr(8 * (size - 3));
      bn.low_u64() as u32
    };

    // Bit 23 denotes the sign. When already set, shift the mantissa right
    // and bump the exponent.
    if compact & 0x0080_0000 != 0 {
      compact >>= 8;
      size += 1;
    }

    compact &= 0x007f_ffff;
    compact |= size << 24;
    if negative && (compact & 0x007f_ffff) != 0 {
      compact |= 0x0080_0000;
    }

    CompactTarget(compact)
  }
}
