//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Buffered codec implementation.

use crate::codec::DecodeError;
use crate::prelude::*;

use bitcoin_consensus_encoding::{Decoder, Encoder};

use core::convert::Infallible;
use core::fmt;

/// Maximum serialized object size (32 MiB).
pub const MAX_SER_SIZE: usize = 0x0200_0000;

/// An encoder that wraps a pre-built byte vector.
#[derive(Clone)]
pub struct VecEncoder {
  data: Vec<u8>,
  done: bool,
}

impl VecEncoder {
  /// Creates a new encoder wrapping the given bytes.
  pub fn new(data: Vec<u8>) -> Self {
    Self { data, done: false }
  }
}

impl fmt::Debug for VecEncoder {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("VecEncoder")
      .field("len", &self.data.len())
      .field("done", &self.done)
      .finish()
  }
}

impl Encoder for VecEncoder {
  fn current_chunk(&self) -> &[u8] {
    if self.done {
      &[]
    } else {
      &self.data
    }
  }

  fn advance(&mut self) -> bool {
    if self.done {
      false
    } else {
      self.done = true;
      false
    }
  }
}

/// A decoder that buffers all input and decodes in `end()`.
///
/// Wraps types with complex sequential decode logic (conditional fields,
/// version branching) that cannot be expressed as a composable push-decoder
/// without excessive boilerplate.
pub struct VecDecoder<T, E = Infallible> {
  buf: Vec<u8>,
  limit: usize,
  decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>,
}

impl<T, E> VecDecoder<T, E> {
  /// Creates a new decoder with the given decode function and
  /// maximum buffer size.
  pub const fn new(decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>, limit: usize) -> Self {
    Self {
      buf: Vec::new(),
      limit,
      decode_fn,
    }
  }
}

impl<T, E> fmt::Debug for VecDecoder<T, E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("VecDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &self.limit)
      .finish()
  }
}

impl<T, E> Clone for VecDecoder<T, E> {
  fn clone(&self) -> Self {
    Self {
      buf: self.buf.clone(),
      limit: self.limit,
      decode_fn: self.decode_fn,
    }
  }
}

impl<T, E> Decoder for VecDecoder<T, E> {
  type Output = T;
  type Error = DecodeError<E>;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    let remaining = self.limit.saturating_sub(self.buf.len());
    if remaining == 0 {
      return Ok(false);
    }
    let take = bytes.len().min(remaining);
    self.buf.extend_from_slice(&bytes[..take]);
    *bytes = &bytes[take..];
    Ok(true)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let mut cursor = &self.buf[..];
    let result = (self.decode_fn)(&mut cursor)?;
    if !cursor.is_empty() {
      return Err(DecodeError::TrailingBytes {
        remaining: cursor.len(),
      });
    }
    Ok(result)
  }

  fn read_limit(&self) -> usize {
    self.limit.saturating_sub(self.buf.len())
  }
}

/// Generates `Encodable` + `Decodable` for a `BaseCodec` implementor.
///
/// Stages through the growable [`VecEncoder`]/[`VecDecoder`] pair. For
/// secret material use [`impl_stype!`](crate::impl_stype) instead, which is
/// the same generator over the wiping fixed-width pair.
#[macro_export]
macro_rules! impl_type {
  (@parse [$($impl_generics:tt)*] $ty:ty, $max:expr, $err:ty) => {
    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Encodable for $ty {
      type Encoder<'e> = $crate::VecEncoder;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = ::alloc::vec::Vec::new();
        $crate::codec::BaseCodec::encode(self, &mut buf);
        $crate::VecEncoder::new(buf)
      }
    }

    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Decodable for $ty {
      type Decoder = $crate::VecDecoder<$ty, $err>;
      fn decoder() -> Self::Decoder {
        $crate::VecDecoder::new(<$ty as $crate::codec::BaseCodec<$err>>::decode, $max)
      }
    }
  };
  (@parse [$($impl_generics:tt)*] $ty:ty, $max:expr) => {
    $crate::impl_type!(
      @parse [$($impl_generics)*] $ty,
      $max,
      ::core::convert::Infallible
    );
  };
  (@parse [$($impl_generics:tt)*] $ty:ty) => {
    $crate::impl_type!(@parse [$($impl_generics)*] $ty, $crate::MAX_SER_SIZE);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_type!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_type!(@parse [] $($args)*);
  };
}

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

    impl<$($g)*> $ty {
      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool { self.as_bytes().iter().all(|&b| b == 0) }
    }

    impl<$($g)*> core::fmt::Debug for $ty {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        $crate::qtypestr(f, ::core::any::type_name::<Self>())?;
        f.write_str("(")?;
        ::core::fmt::Display::fmt(self, f)?;
        f.write_str(")")
      }
    }

    impl<$($g)*> core::fmt::Display for $ty {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
          ::core::write!(f, "{byte:02x}")?;
        }
        ::core::result::Result::Ok(())
      }
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
    }
  };
}
