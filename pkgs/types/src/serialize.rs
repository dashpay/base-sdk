//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

/// Wire-order hex for `Vec<u8>`.
pub mod hex {
  use crate::prelude::*;

  use hex_conservative::{DisplayHex, FromHex};

  /// Serializes bytes as a wire-order hex string.
  ///
  /// # Errors
  ///
  /// Returns a serialization error when the serializer rejects the string.
  pub fn serialize<S: ::serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&data.to_lower_hex_string())
  }

  /// Deserializes a hex string into bytes.
  ///
  /// # Errors
  ///
  /// Returns a deserialization error when the input is not a string, or when
  /// it is not valid hex.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
    Vec::<u8>::from_hex(&s).map_err(::serde::de::Error::custom)
  }
}

/// Serializes `u64` as a decimal string to avoid JSON precision loss.
pub mod str_u64 {
  /// Serializes a `u64` as a decimal string.
  pub fn serialize<S: ::serde::Serializer>(val: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&alloc::format!("{val}"))
  }

  /// Deserializes a `u64` from a decimal string or a number.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    struct Visitor;

    impl ::serde::de::Visitor<'_> for Visitor {
      type Value = u64;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("u64 as string or number")
      }

      fn visit_u64<E: ::serde::de::Error>(self, v: u64) -> Result<u64, E> {
        Ok(v)
      }

      fn visit_str<E: ::serde::de::Error>(self, s: &str) -> Result<u64, E> {
        s.parse().map_err(E::custom)
      }
    }

    d.deserialize_any(Visitor)
  }
}

/// UTF-8 serde for `Vec<u8>` fields that hold text.
pub mod utf8 {
  use crate::prelude::*;

  use core::str::from_utf8;

  /// Serializes bytes as a UTF-8 string.
  ///
  /// # Errors
  ///
  /// Returns a serialization error when bytes are not valid UTF-8.
  pub fn serialize<S: ::serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    let s = from_utf8(data).map_err(::serde::ser::Error::custom)?;
    serializer.serialize_str(s)
  }

  /// Deserializes a string into bytes.
  ///
  /// # Errors
  ///
  /// Returns a deserialization error when the input is not a valid string.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
    Ok(s.into_bytes())
  }
}
