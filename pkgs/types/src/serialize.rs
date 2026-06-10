//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

pub use crate::hex::serde as hex;

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
