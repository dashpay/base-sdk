//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size byte newtype macro and decoder.

/// Generates a fixed-size byte newtype with consensus encoding traits and
/// standard trait implementations.
macro_rules! define_byte_type {
  (
    $(#[$attr:meta])*
    $name:ident, $n:literal
  ) => {
    $(#[$attr])*
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct $name(pub [u8; $n]);

    impl Default for $name {
      fn default() -> Self { Self([0u8; $n]) }
    }

    impl $name {
      /// Returns the inner byte array.
      pub const fn to_byte_array(self) -> [u8; $n] {
        self.0
      }

      /// Returns a reference to the inner byte array.
      pub const fn as_byte_array(&self) -> &[u8; $n] {
        &self.0
      }

      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
      }
    }

    impl From<[u8; $n]> for $name {
      fn from(bytes: [u8; $n]) -> Self { Self(bytes) }
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

    impl bitcoin_consensus_encoding::Encodable for $name {
      type Encoder<'e> = bitcoin_consensus_encoding::ArrayRefEncoder<'e, $n>;

      fn encoder(&self) -> Self::Encoder<'_> {
        bitcoin_consensus_encoding::ArrayRefEncoder::without_length_prefix(&self.0)
      }
    }

    impl bitcoin_consensus_encoding::Decodable for $name {
      type Decoder = $crate::types::byte::ByteTypeDecoder<$name, $n>;
      fn decoder() -> Self::Decoder { $crate::types::byte::ByteTypeDecoder::new() }
    }
  };
}

pub(crate) use define_byte_type;

/// Generic decoder for fixed-size byte newtypes.
#[derive(Debug)]
pub struct ByteTypeDecoder<T, const N: usize>(
  bitcoin_consensus_encoding::ArrayDecoder<N>,
  core::marker::PhantomData<T>,
);

impl<T, const N: usize> ByteTypeDecoder<T, N> {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(
      bitcoin_consensus_encoding::ArrayDecoder::new(),
      core::marker::PhantomData,
    )
  }
}

impl<T, const N: usize> Default for ByteTypeDecoder<T, N> {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for fixed-size byte newtypes.
#[derive(Debug)]
pub struct ByteTypeDecoderError(pub bitcoin_consensus_encoding::UnexpectedEofError);

impl core::fmt::Display for ByteTypeDecoderError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "byte type decode: {}", self.0)
  }
}

impl<T, const N: usize> bitcoin_consensus_encoding::Decoder for ByteTypeDecoder<T, N>
where
  T: From<[u8; N]>,
{
  type Output = T;
  type Error = ByteTypeDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(ByteTypeDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    self.0.end().map(T::from).map_err(ByteTypeDecoderError)
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}
