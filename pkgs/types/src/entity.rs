//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridge utilities for `BaseCodec` types to `bitcoin_consensus_encoding`
//! traits.

use crate::codec::DecodeError;
use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// Maximum serialized object size (32 MiB).
pub const MAX_SER_SIZE: usize = 0x0200_0000;

/// A decoder that buffers all input and decodes in `end()`.
///
/// Wraps types with complex sequential decode logic (conditional fields,
/// version branching) that cannot be expressed as a composable push-decoder
/// without excessive boilerplate.
pub struct BufferDecoder<T> {
  buf: Vec<u8>,
  limit: usize,
  decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError>,
}

impl<T> BufferDecoder<T> {
  /// Creates a new decoder with the given decode function and
  /// maximum buffer size.
  pub const fn new(decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError>, limit: usize) -> Self {
    Self {
      buf: Vec::new(),
      limit,
      decode_fn,
    }
  }
}

impl<T> fmt::Debug for BufferDecoder<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BufferDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &self.limit)
      .finish()
  }
}

impl<T> Clone for BufferDecoder<T> {
  fn clone(&self) -> Self {
    Self {
      buf: self.buf.clone(),
      limit: self.limit,
      decode_fn: self.decode_fn,
    }
  }
}

impl<T> encoding::Decoder for BufferDecoder<T> {
  type Output = T;
  type Error = DecodeError;

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

/// An encoder that wraps a pre-built byte vector.
#[derive(Clone, Debug)]
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

impl encoding::Encoder for VecEncoder {
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

/// Generates `Encodable` + `Decodable` for a `BaseCodec` implementor.
#[macro_export]
macro_rules! impl_type {
  ($ty:ty) => {
    $crate::impl_type!($ty, $crate::MAX_SER_SIZE);
  };
  ($ty:ty, $max:expr) => {
    impl ::bitcoin_consensus_encoding::Encodable for $ty {
      type Encoder<'e> = $crate::VecEncoder;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = ::alloc::vec::Vec::new();
        $crate::codec::BaseCodec::encode(self, &mut buf);
        $crate::VecEncoder::new(buf)
      }
    }

    impl ::bitcoin_consensus_encoding::Decodable for $ty {
      type Decoder = $crate::BufferDecoder<$ty>;
      fn decoder() -> Self::Decoder {
        $crate::BufferDecoder::new(<$ty as $crate::codec::BaseCodec>::decode, $max)
      }
    }
  };
}
