//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size opaque hash blob types.

use hex_conservative::{BytesToHexIter, Case, HexToBytesIter};

use core::fmt::{self, Write as _};
use core::hash::Hash;
use core::str::FromStr;

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

macro_rules! define_hash {
  ($name:ident, $n:literal) => {
    /// Fixed-size opaque hash blob stored in little-endian byte order.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct $name([u8; $n]);

    impl $name {
      /// The all-zeros (null) hash.
      pub const ZERO: Self = Self([0u8; $n]);
      /// Byte length of this hash type.
      pub const LEN: usize = $n;

      /// Wrap raw little-endian bytes into a hash.
      #[inline]
      pub fn from_bytes(bytes: [u8; $n]) -> Self {
        Self(bytes)
      }

      /// Return the raw little-endian bytes.
      #[inline]
      pub fn to_bytes(self) -> [u8; $n] {
        self.0
      }

      /// Borrow the raw little-endian bytes.
      #[inline]
      pub fn as_bytes(&self) -> &[u8; $n] {
        &self.0
      }

      /// Construct from big-endian bytes (consensus display order).
      ///
      /// This is the natural byte order produced by `hex_literal::hex!()` when
      /// given a block hash or other consensus hex value. Internally the bytes
      /// are stored little-endian, so this reverses the input.
      #[inline]
      pub const fn new(be: [u8; $n]) -> Self {
        let mut le = [0u8; $n];
        let mut i = 0;
        while i < $n {
          le[i] = be[$n - 1 - i];
          i += 1;
        }
        Self(le)
      }

      /// Returns `true` if every byte is zero.
      pub fn is_null(&self) -> bool {
        let mut i = 0;
        while i < $n {
          if self.0[i] != 0 {
            return false;
          }
          i += 1;
        }
        true
      }

      /// Parse from a big-endian hex string.
      ///
      /// Accepts an optional `0x`/`0X` prefix followed by optional leading
      /// spaces before the hex digits. The digits are big-endian (MSB first),
      /// mirroring the consensus display convention.
      ///
      /// # Errors
      ///
      /// Returns `OddLength` when input has an odd number of hex characters,
      /// `InvalidLength` when the decoded byte count exceeds the type width, or
      /// `InvalidChar` on a non-hex digit.
      pub fn from_hex(s: &str) -> Result<Self, ParseHexError> {
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        let s = s.trim_start_matches(' ');

        if s.len() > $n * 2 {
          return Err(ParseHexError::InvalidLength {
            expected: $n * 2,
            got: s.len(),
          });
        }

        let digits = HexToBytesIter::new(s).map_err(|_| ParseHexError::OddLength)?;
        let mut bytes = [0u8; $n];
        for (slot, byte) in bytes.iter_mut().zip(digits.rev()) {
          *slot = byte.map_err(|e| ParseHexError::InvalidChar(e.invalid_char()))?;
        }

        Ok(Self(bytes))
      }
    }

    impl Default for $name {
      fn default() -> Self {
        Self::ZERO
      }
    }

    impl Ord for $name {
      fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        // Lexicographic on raw bytes (consensus ordering).
        self.0.cmp(&other.0)
      }
    }

    impl PartialOrd for $name {
      fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
        Some(self.cmp(other))
      }
    }

    /// Reversed hex (big-endian display, consensus format).
    impl fmt::Display for $name {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in BytesToHexIter::new(self.0.iter().rev().copied(), Case::Lower) {
          f.write_char(c)?;
        }
        Ok(())
      }
    }

    impl fmt::LowerHex for $name {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
      }
    }

    impl fmt::Debug for $name {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", stringify!($name), self)
      }
    }

    impl FromStr for $name {
      type Err = ParseHexError;

      fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
      }
    }

    $crate::__private::dash_types::type_cvrt!(From<[u8; $n]> for $name, |b| Self(*b));
    $crate::__private::dash_types::type_cvrt!(From<$name> for [u8; $n], |h| h.0);

    impl AsRef<[u8]> for $name {
      fn as_ref(&self) -> &[u8] {
        &self.0
      }
    }

    impl AsRef<[u8; $n]> for $name {
      fn as_ref(&self) -> &[u8; $n] {
        &self.0
      }
    }

    $crate::cfg_codec! {
      impl $crate::__private::dash_types::codec::BaseCodec for $name {
        fn decode(data: &mut &[u8]) -> Result<Self, $crate::__private::dash_types::codec::DecodeError> {
          $crate::__private::dash_types::codec::take::<$n>(data).map(Self::from_bytes)
        }

        fn encode(&self, buf: &mut impl $crate::__private::dash_types::codec::EncodeBuf) {
          buf.extend_from_slice(&self.0);
        }
      }

      $crate::__private::dash_types::impl_type!($name);
    }

    #[cfg(feature = "serde")]
    impl ::serde::Serialize for $name {
      fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&::alloc::format!("{}", self))
      }
    }

    #[cfg(feature = "serde")]
    impl<'de> ::serde::Deserialize<'de> for $name {
      fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <::alloc::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(::serde::de::Error::custom)
      }
    }
  };
}

define_hash!(Hash160, 20);
define_hash!(Hash256, 32);
