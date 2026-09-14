//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size opaque hash blob types.

#[cfg(feature = "codec")]
use dash_types::impl_type;
use dash_types::{type_cvrt, Numeric};
use hex_conservative::{BytesToHexIter, Case, HexToBytesIter};

use core::fmt::{self, Write as _};
use core::hash::Hash;
use core::str::FromStr;

/// Whitespace skipped before a hex prefix.
const WHITESPACE: [char; 6] = [' ', '\x0c', '\n', '\r', '\t', '\x0b'];

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

/// Fixed-size opaque hash blob stored in little-endian byte order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashBlob<const N: usize>([u8; N]);

impl<const N: usize> Numeric for HashBlob<N> {
  type Base = [u8; N];

  type Bytes = [u8; N];

  const ZERO: Self = Self([0u8; N]);

  #[inline]
  fn from_base(v: [u8; N]) -> Self {
    Self(v)
  }

  #[inline]
  fn to_base(&self) -> [u8; N] {
    self.0
  }

  #[inline]
  fn from_lendian(bytes: [u8; N]) -> Self {
    Self(bytes)
  }

  #[inline]
  fn to_lendian(&self) -> [u8; N] {
    self.0
  }

  #[inline]
  fn from_bendian(bytes: [u8; N]) -> Self {
    // Resolves to the inherent `const` form.
    Self::from_bendian(bytes)
  }

  #[inline]
  fn to_bendian(&self) -> [u8; N] {
    <[u8; N] as Numeric>::to_bendian(&self.0)
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> dash_types::codec::BaseCodec for HashBlob<N> {
  fn decode(data: &mut &[u8]) -> Result<Self, dash_types::codec::DecodeError> {
    dash_types::codec::take::<N>(data).map(<Self as Numeric>::from_lendian)
  }

  fn encode(&self, buf: &mut impl dash_types::codec::EncodeBuf) {
    buf.extend_from_slice(&self.0);
  }
}

#[cfg(feature = "codec")]
impl_type!(for[const N: usize] HashBlob<N>, N);

impl<const N: usize> HashBlob<N> {
  /// Borrow the raw little-endian bytes.
  #[inline]
  pub fn as_bytes(&self) -> &[u8; N] {
    &self.0
  }

  /// Construct from big-endian bytes (consensus display order).
  ///
  /// This is the natural byte order produced by `hex_literal::hex!()` when
  /// given a block hash or other consensus hex value. Internally the bytes
  /// are stored little-endian, so this reverses the input.
  #[inline]
  pub const fn from_bendian(be: [u8; N]) -> Self {
    let mut le = [0u8; N];
    let mut i = 0;
    while i < N {
      le[i] = be[N - 1 - i];
      i += 1;
    }
    Self(le)
  }

  /// Returns `true` if every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0 == [0u8; N]
  }

  /// Parse from a big-endian hex string.
  ///
  /// Accepts leading whitespace followed by an optional `0x`/`0X` prefix,
  /// in that order. The digits are big-endian (MSB first), mirroring the
  /// consensus display convention.
  ///
  /// # Errors
  ///
  /// Returns `OddLength` when input has an odd number of hex characters,
  /// `InvalidLength` when the hex character count exceeds the type width, or
  /// `InvalidChar` on a non-hex digit.
  pub fn from_hex(s: &str) -> Result<Self, ParseHexError> {
    let s = s.trim_start_matches(WHITESPACE);
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

    if s.len() > N * 2 {
      return Err(ParseHexError::InvalidLength {
        expected: N * 2,
        got: s.len(),
      });
    }

    let digits = HexToBytesIter::new(s).map_err(|_| ParseHexError::OddLength)?;
    let mut bytes = [0u8; N];
    for (slot, byte) in bytes.iter_mut().zip(digits.rev()) {
      *slot = byte.map_err(|e| ParseHexError::InvalidChar(e.invalid_char()))?;
    }

    Ok(Self(bytes))
  }
}

impl<const N: usize> Default for HashBlob<N> {
  fn default() -> Self {
    Self::ZERO
  }
}

/// Reversed hex (big-endian display, consensus format).
impl<const N: usize> fmt::Display for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write_hex(self.as_bytes(), Case::Lower, f)
  }
}

/// Big-endian hex, `N * 2` chars zero-padded.
impl<const N: usize> fmt::LowerHex for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write_hex(self.as_bytes(), Case::Lower, f)
  }
}

/// Big-endian hex (uppercase), `N * 2` chars zero-padded.
impl<const N: usize> fmt::UpperHex for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write_hex(self.as_bytes(), Case::Upper, f)
  }
}

/// Writes little-endian storage as big-endian hex, honouring `{:#x}`.
fn write_hex(bytes: &[u8], case: Case, f: &mut fmt::Formatter<'_>) -> fmt::Result {
  if f.alternate() {
    f.write_str(if case == Case::Lower { "0x" } else { "0X" })?;
  }
  for c in BytesToHexIter::new(bytes.iter().rev().copied(), case) {
    f.write_char(c)?;
  }
  Ok(())
}

impl<const N: usize> fmt::Debug for HashBlob<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "HashBlob<{N}>({self})")
  }
}

impl<const N: usize> FromStr for HashBlob<N> {
  type Err = ParseHexError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::from_hex(s)
  }
}

type_cvrt!(for[const N: usize] From<[u8; N]> for HashBlob<N>, |b| Self(*b));
type_cvrt!(for[const N: usize] From<HashBlob<N>> for [u8; N], |h| h.0);

impl<const N: usize> AsRef<[u8]> for HashBlob<N> {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl<const N: usize> AsRef<[u8; N]> for HashBlob<N> {
  fn as_ref(&self) -> &[u8; N] {
    &self.0
  }
}

#[cfg(feature = "serde")]
impl<const N: usize> ::serde::Serialize for HashBlob<N> {
  fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&::alloc::format!("{}", self))
  }
}

#[cfg(feature = "serde")]
impl<'de, const N: usize> ::serde::Deserialize<'de> for HashBlob<N> {
  fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let s = <::alloc::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
    Self::from_hex(&s).map_err(::serde::de::Error::custom)
  }
}

/// 160-bit hash blob.
pub type Hash160 = HashBlob<20>;

/// 256-bit hash blob.
pub type Hash256 = HashBlob<32>;
