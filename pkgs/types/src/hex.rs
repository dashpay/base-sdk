//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size byte newtype macros.

/// Generates `BaseCodec` + `Encodable` + `Decodable` + `From<[u8; N]>`
/// for a fixed-size byte newtype that wraps `[u8; N]` and exposes
/// `as_bytes()`.
#[macro_export]
macro_rules! impl_bytes {
  ($n:literal, $($name:ident),* $(,)?) => { $(
    impl $crate::codec::BaseCodec for $name {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::codec::DecodeError> {
        $crate::codec::take::<$n>(data).map(|b| Self(b))
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        buf.extend_from_slice(self.as_bytes());
      }
    }

    $crate::impl_type!($name);

    impl From<[u8; $n]> for $name {
      fn from(bytes: [u8; $n]) -> Self { Self(bytes) }
    }
  )* };
}

/// Generates a fixed-size byte newtype with consensus encoding traits and
/// standard trait implementations.
#[macro_export]
macro_rules! make_bytes {
  (
    $(#[$attr:meta])*
    $name:ident, $n:literal
  ) => {
    $(#[$attr])*
    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    pub struct $name(pub [u8; $n]);

    $crate::impl_bytes!($n, $name);

    impl $name {
      /// Returns the inner byte array.
      pub const fn to_bytes(self) -> [u8; $n] {
        self.0
      }

      /// Borrows the inner byte array.
      pub const fn as_bytes(&self) -> &[u8; $n] {
        &self.0
      }

      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
      }
    }

    impl Default for $name {
      fn default() -> Self { Self([0u8; $n]) }
    }

    impl From<$name> for [u8; $n] {
      fn from(val: $name) -> Self { val.0 }
    }

    impl AsRef<[u8]> for $name {
      fn as_ref(&self) -> &[u8] { &self.0 }
    }

    impl AsRef<[u8; $n]> for $name {
      fn as_ref(&self) -> &[u8; $n] { &self.0 }
    }

    impl core::fmt::Debug for $name {
      fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
      ) -> core::fmt::Result {
        write!(f, "{}(", stringify!($name))?;
        for byte in &self.0 {
          write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
      }
    }

    impl core::fmt::Display for $name {
      fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
      ) -> core::fmt::Result {
        for byte in &self.0 {
          write!(f, "{:02x}", byte)?;
        }
        Ok(())
      }
    }

    #[cfg(feature = "serde")]
    impl ::serde::Serialize for $name {
      fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use $crate::__private::hex_conservative::DisplayHex;
        serializer.serialize_str(&self.0.to_lower_hex_string())
      }
    }

    #[cfg(feature = "serde")]
    impl<'de> ::serde::Deserialize<'de> for $name {
      fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <::alloc::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
        <[u8; $n] as $crate::__private::hex_conservative::FromHex>::from_hex(&s)
          .map(Self)
          .map_err(::serde::de::Error::custom)
      }
    }
  };
}

/// Wire-order hex for `Vec<u8>` and fixed-size byte arrays.
///
/// Use with `#[serde(with = "dash_types::serialize::hex")]` on
/// `Vec<u8>` fields. For fixed-size byte arrays use a sub-module
/// (e.g. `hex::w16` for `[u8; 16]`).
#[cfg(feature = "serde")]
pub mod serde {
  use crate::prelude::*;

  use hex_conservative::{DisplayHex, FromHex};

  /// Serializes bytes as a wire-order hex string.
  pub fn serialize<S: ::serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&data.to_lower_hex_string())
  }

  /// Deserializes a hex string into bytes.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
    Vec::<u8>::from_hex(&s).map_err(::serde::de::Error::custom)
  }
}
