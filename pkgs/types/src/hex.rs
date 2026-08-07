//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size byte newtype macros.

/// Generates `BaseCodec` + `Encodable` + `Decodable` + `From<[u8; N]>` for a
/// fixed-size byte newtype, expressed only through `from_bytes` / `as_bytes`.
///
/// Staged through the growable [`VecEncoder`]. For a newtype whose contents
/// are secret use [`impl_sbytes!`](crate::impl_sbytes).
#[macro_export]
macro_rules! impl_bytes {
  // Shared by `impl_bytes!` and `impl_sbytes!`, only the encoder pair differs.
  (@codec [$($g:tt)*] $ty:ty, $n:expr) => {
    impl<$($g)*> $crate::codec::BaseCodec for $ty {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::codec::DecodeError> {
        $crate::codec::take::<$n>(data).map(Self::from_bytes)
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        buf.extend_from_slice(self.as_bytes());
      }
    }

    impl<$($g)*> ::core::convert::From<[u8; $n]> for $ty {
      fn from(bytes: [u8; $n]) -> Self { Self::from_bytes(bytes) }
    }
  };
  (@parse [$($g:tt)*] $ty:ty, $n:expr) => {
    $crate::impl_bytes!(@codec [$($g)*] $ty, $n);

    $crate::impl_type!(@parse [$($g)*] $ty, $n);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_bytes!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_bytes!(@parse [] $($args)*);
  };
}

/// The standard trait set for a fixed-size byte newtype, expressed only
/// through `from_bytes` / `as_bytes`.
///
/// Emits `Clone`, `Copy`, `Default`, `Eq`, `PartialEq`, `Ord`, `PartialOrd`,
/// `Hash`, `AsRef<[u8]>`, `AsRef<[u8; N]>`, `From<Self> for [u8; N]`, and the
/// hex `serde` pair.
#[macro_export]
macro_rules! derive_bytes {
  (@parse [$($g:tt)*] $ty:ty, $n:expr) => {
    impl<$($g)*> ::core::clone::Clone for $ty {
      fn clone(&self) -> Self { *self }
    }

    impl<$($g)*> ::core::marker::Copy for $ty {}

    impl<$($g)*> ::core::default::Default for $ty {
      fn default() -> Self { Self::from_bytes([0u8; $n]) }
    }

    impl<$($g)*> ::core::cmp::Eq for $ty {}

    impl<$($g)*> ::core::cmp::PartialEq for $ty {
      fn eq(&self, other: &Self) -> bool { self.as_bytes() == other.as_bytes() }
    }

    impl<$($g)*> ::core::cmp::Ord for $ty {
      fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
      }
    }

    impl<$($g)*> ::core::cmp::PartialOrd for $ty {
      fn partial_cmp(&self, other: &Self) -> ::core::option::Option<::core::cmp::Ordering> {
        ::core::option::Option::Some(::core::cmp::Ord::cmp(self, other))
      }
    }

    impl<$($g)*> ::core::hash::Hash for $ty {
      fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
        ::core::hash::Hash::hash(self.as_bytes(), state);
      }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8]> for $ty {
      fn as_ref(&self) -> &[u8] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8; $n]> for $ty {
      fn as_ref(&self) -> &[u8; $n] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::From<$ty> for [u8; $n] {
      fn from(val: $ty) -> Self { *val.as_bytes() }
    }

    #[cfg(feature = "serde")]
    impl<$($g)*> ::serde::Serialize for $ty {
      fn serialize<Z: ::serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        use $crate::__private::hex_conservative::DisplayHex as _;
        serializer.serialize_str(&self.as_bytes().to_lower_hex_string())
      }
    }

    #[cfg(feature = "serde")]
    impl<'de, $($g)*> ::serde::Deserialize<'de> for $ty {
      fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use ::serde::de::Error as _;
        let s = <::alloc::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
        <[u8; $n] as $crate::__private::hex_conservative::FromHex>::from_hex(&s)
          .map(Self::from_bytes)
          .map_err(D::Error::custom)
      }
    }
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::derive_bytes!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::derive_bytes!(@parse [] $($args)*);
  };
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
    #[derive($crate::TypeId)]
    pub struct $name(pub [u8; $n]);

    $crate::impl_bytes!($name, $n);

    $crate::derive_bytes!($name, $n);

    impl $name {
      /// Wraps raw bytes without validation.
      pub const fn from_bytes(bytes: [u8; $n]) -> Self {
        Self(bytes)
      }

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
  };
}
