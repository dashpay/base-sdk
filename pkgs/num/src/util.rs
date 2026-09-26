//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hash newtype macros.

/// dash-num's [`cfg_codec!`](dash_types::cfg_codec), keyed to `dash-num/codec`
/// (this crate) rather than `dash-types/codec`.
///
/// `{ .. } else { .. }` picks between two bodies rather than emitting one
/// conditionally, for an item that exists either way.
#[cfg(feature = "codec")]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_codec {
  ({$($with:tt)*} else {$($without:tt)*}) => { $($with)* };
  ($($item:tt)*) => { $($item)* };
}

#[cfg(not(feature = "codec"))]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_codec {
  ({$($with:tt)*} else {$($without:tt)*}) => { $($without)* };
  ($($item:tt)*) => {};
}

/// dash-num's [`cfg_serde!`](dash_types::cfg_serde), keyed to `dash-num/serde`
/// (this crate) rather than `dash-types/serde`.
#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => { $($item)* };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => {};
}

/// Generates a newtype wrapping a hash base type with full trait
/// implementations and consensus encoding support.
#[macro_export]
macro_rules! make_hash {
  // The codec half, split out for gating with `cfg_codec!`.
  (@codec $len:literal, $name:ident) => {
    $crate::cfg_codec! {
    impl $crate::__deps::dash_types::codec::BaseCodec for $name {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::__deps::dash_types::codec::DecodeError> {
        $crate::__deps::dash_types::codec::take::<$len>(data)
          .map(<Self as $crate::__deps::dash_types::Numeric>::from_lendian)
      }

      fn encode(&self, buf: &mut impl $crate::__deps::dash_types::codec::EncodeBuf) {
        buf.extend_from_slice(self.as_bytes());
      }
    }

    $crate::__deps::dash_types::impl_type!($name);
    }
  };
  (
    $(#[$attr:meta])*
    $name:ident, $len:literal
  ) => {
    $crate::cfg_codec! {
      {
        $(#[$attr])*
        #[derive(
          Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
          $crate::__deps::dash_types::type_id::TypeId,
        )]
        pub struct $name($crate::HashBlob<$len>);
      } else {
        $(#[$attr])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($crate::HashBlob<$len>);
      }
    }

    $crate::cfg_serde! {
      impl $crate::__private::serde::Serialize for $name {
        fn serialize<S: $crate::__private::serde::Serializer>(
          &self, serializer: S,
        ) -> Result<S::Ok, S::Error> {
          $crate::__private::serde::Serialize::serialize(&self.0, serializer)
        }
      }

      impl<'de> $crate::__private::serde::Deserialize<'de> for $name {
        fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
          deserializer: D,
        ) -> Result<Self, D::Error> {
          <$crate::HashBlob<$len> as $crate::__private::serde::Deserialize>::deserialize(deserializer).map(Self)
        }
      }
    }

    impl $name {
      /// Borrow the raw little-endian bytes.
      #[inline]
      pub fn as_bytes(&self) -> &[u8; $len] {
        self.0.as_bytes()
      }

      /// Returns `true` if every byte is zero.
      #[inline]
      pub fn is_null(&self) -> bool {
        self.0.is_null()
      }

      /// Parse from a big-endian hex string.
      #[inline]
      pub fn from_hex(s: &str) -> Result<Self, $crate::__deps::dash_types::ParseHexError> {
        <$crate::HashBlob<$len>>::from_hex(s).map(Self)
      }
    }

    impl $crate::__deps::dash_types::Numeric for $name {
      type Base = $crate::HashBlob<$len>;

      type Bytes = [u8; $len];

      const ZERO: Self = Self(<$crate::HashBlob<$len> as $crate::__deps::dash_types::Numeric>::ZERO);

      #[inline]
      fn from_base(v: $crate::HashBlob<$len>) -> Self {
        Self(v)
      }

      #[inline]
      fn to_base(&self) -> $crate::HashBlob<$len> {
        self.0
      }

      #[inline]
      fn from_lendian(bytes: [u8; $len]) -> Self {
        Self(<$crate::HashBlob<$len> as $crate::__deps::dash_types::Numeric>::from_lendian(bytes))
      }

      #[inline]
      fn to_lendian(&self) -> [u8; $len] {
        <$crate::HashBlob<$len> as $crate::__deps::dash_types::Numeric>::to_lendian(&self.0)
      }

      #[inline]
      fn from_bendian(bytes: [u8; $len]) -> Self {
        Self(<$crate::HashBlob<$len> as $crate::__deps::dash_types::Numeric>::from_bendian(bytes))
      }

      #[inline]
      fn to_bendian(&self) -> [u8; $len] {
        <$crate::HashBlob<$len> as $crate::__deps::dash_types::Numeric>::to_bendian(&self.0)
      }
    }

    impl Default for $name {
      #[inline]
      fn default() -> Self { <Self as $crate::__deps::dash_types::Numeric>::ZERO }
    }

    impl ::core::fmt::Display for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::fmt::Display::fmt(&self.0, f)
      }
    }

    impl ::core::fmt::LowerHex for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::fmt::LowerHex::fmt(&self.0, f)
      }
    }

    impl ::core::fmt::UpperHex for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::fmt::UpperHex::fmt(&self.0, f)
      }
    }

    impl ::core::fmt::Debug for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "{}({})", stringify!($name), self.0)
      }
    }

    impl ::core::str::FromStr for $name {
      type Err = $crate::__deps::dash_types::ParseHexError;

      fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
      }
    }

    $crate::__deps::dash_types::type_cvrt!(From<[u8; $len]> for $name, |b| <Self as $crate::__deps::dash_types::Numeric>::from_lendian(*b));
    $crate::__deps::dash_types::type_cvrt!(From<$name> for [u8; $len], |h| $crate::__deps::dash_types::Numeric::to_lendian(h));
    $crate::__deps::dash_types::type_cvrt!(From<$crate::HashBlob<$len>> for $name, |h| Self(*h));
    $crate::__deps::dash_types::type_cvrt!(From<$name> for $crate::HashBlob<$len>, |h| h.0);

    impl AsRef<[u8]> for $name {
      #[inline]
      fn as_ref(&self) -> &[u8] { self.0.as_ref() }
    }

    impl AsRef<[u8; $len]> for $name {
      #[inline]
      fn as_ref(&self) -> &[u8; $len] { self.0.as_bytes() }
    }

    $crate::make_hash!(@codec $len, $name);
  };
}
