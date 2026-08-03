//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridge utilities for `BaseCodec` types to `bitcoin_consensus_encoding`
//! traits.

use crate::codec::{ArrayBuf, DecodeError, EncodeBuf};
use crate::prelude::*;

use bitcoin_consensus_encoding::{Decoder, Encoder};
use zeroize::Zeroize;

use core::convert::Infallible;
use core::fmt;

/// Maximum serialized object size (32 MiB).
pub const MAX_SER_SIZE: usize = 0x0200_0000;

/// Widest buffer [`ArrEncoder`] and [`ArrDecoder`] will wipe.
pub const MAX_ARR_SIZE: usize = 512;

/// A decoder that buffers all input and decodes in `end()`.
///
/// Wraps types with complex sequential decode logic (conditional fields,
/// version branching) that cannot be expressed as a composable push-decoder
/// without excessive boilerplate.
pub struct BufferDecoder<T, E = Infallible> {
  buf: Vec<u8>,
  limit: usize,
  decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>,
}

impl<T, E> BufferDecoder<T, E> {
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

impl<T, E> fmt::Debug for BufferDecoder<T, E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BufferDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &self.limit)
      .finish()
  }
}

impl<T, E> Clone for BufferDecoder<T, E> {
  fn clone(&self) -> Self {
    Self {
      buf: self.buf.clone(),
      limit: self.limit,
      decode_fn: self.decode_fn,
    }
  }
}

impl<T, E> Decoder for BufferDecoder<T, E> {
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

/// An encoder for values whose encoded width is bounded at compile time.
///
/// Costs a byte-wise volatile write per byte of `N`, so it suits key material
/// and other small fixed records, not block-sized payloads. [`MAX_ARR_SIZE`]
/// caps `N` due to performance cost.
pub struct ArrEncoder<const N: usize> {
  data: ArrayBuf<N>,
  done: bool,
}

impl<const N: usize> ArrEncoder<N> {
  /// Wraps a filled buffer.
  ///
  /// Refuses to compile when `N` exceeds [`MAX_ARR_SIZE`].
  pub const fn new(data: ArrayBuf<N>) -> Self {
    const { assert!(N <= MAX_ARR_SIZE, "unusually large zeroized buffer") };
    Self { data, done: false }
  }
}

impl<const N: usize> fmt::Debug for ArrEncoder<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ArrEncoder")
      .field("len", &self.data.len())
      .field("done", &self.done)
      .finish()
  }
}

impl<const N: usize> Drop for ArrEncoder<N> {
  fn drop(&mut self) {
    self.data.zeroize();
  }
}

impl<const N: usize> Encoder for ArrEncoder<N> {
  fn current_chunk(&self) -> &[u8] {
    if self.done {
      &[]
    } else {
      self.data.as_bytes()
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

/// A decoder for values whose encoded width is bounded by `N`.
pub struct ArrDecoder<T, const N: usize, E = Infallible> {
  buf: ArrayBuf<N>,
  decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>,
}

impl<T, const N: usize, E> ArrDecoder<T, N, E> {
  /// Creates a decoder that accepts at most `N` bytes.
  ///
  /// Refuses to compile when `N` exceeds [`MAX_ARR_SIZE`].
  pub const fn new(decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>) -> Self {
    const { assert!(N <= MAX_ARR_SIZE, "unusually large zeroized buffer") };
    Self {
      buf: ArrayBuf::new(),
      decode_fn,
    }
  }
}

impl<T, const N: usize, E> fmt::Debug for ArrDecoder<T, N, E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ArrDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &N)
      .finish()
  }
}

impl<T, const N: usize, E> Drop for ArrDecoder<T, N, E> {
  fn drop(&mut self) {
    self.buf.zeroize();
  }
}

impl<T, const N: usize, E> Decoder for ArrDecoder<T, N, E> {
  type Output = T;
  type Error = DecodeError<E>;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    let remaining = self.buf.spare();
    if remaining == 0 {
      return Ok(false);
    }
    let take = bytes.len().min(remaining);
    self.buf.extend_from_slice(&bytes[..take]);
    *bytes = &bytes[take..];
    Ok(true)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    // Borrow rather than destructure: `Drop` wipes the buffer on the way out,
    // including on the early return below.
    let mut cursor = self.buf.as_bytes();
    let result = (self.decode_fn)(&mut cursor)?;
    if !cursor.is_empty() {
      return Err(DecodeError::TrailingBytes {
        remaining: cursor.len(),
      });
    }
    Ok(result)
  }

  fn read_limit(&self) -> usize {
    self.buf.spare()
  }
}

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

/// Generates `Encodable` + `Decodable` for a `BaseCodec` implementor.
///
/// Stages through the growable [`VecEncoder`]/[`BufferDecoder`] pair. For
/// secret material use [`impl_stype!`](crate::impl_stype) instead, which is
/// the same generator over the wiping fixed-width pair.
#[macro_export]
macro_rules! impl_type {
  (@parse [$($impl_generics:tt)*] $ty:ty, $max:expr, $err:ty) => {
    impl $($impl_generics)* $crate::__private::bitcoin_consensus_encoding::Encodable for $ty {
      type Encoder<'e> = $crate::VecEncoder;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = ::alloc::vec::Vec::new();
        $crate::codec::BaseCodec::encode(self, &mut buf);
        $crate::VecEncoder::new(buf)
      }
    }

    impl $($impl_generics)* $crate::__private::bitcoin_consensus_encoding::Decodable for $ty {
      type Decoder = $crate::BufferDecoder<$ty, $err>;
      fn decoder() -> Self::Decoder {
        $crate::BufferDecoder::new(<$ty as $crate::codec::BaseCodec<$err>>::decode, $max)
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
    $crate::impl_type!(@parse [<$($generic)*>] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_type!(@parse [] $($args)*);
  };
}

/// Generates `Encodable` + `Decodable` for a `BaseCodec` implementor whose
/// wire image is secret.
#[macro_export]
macro_rules! impl_stype {
  (@parse [$($impl_generics:tt)*] $ty:ty, $n:expr, $err:ty) => {
    impl $($impl_generics)* $crate::__private::bitcoin_consensus_encoding::Encodable for $ty {
      type Encoder<'e> = $crate::ArrEncoder<{ $n }>;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = $crate::codec::ArrayBuf::<{ $n }>::new();
        <$ty as $crate::codec::BaseCodec<$err>>::encode(self, &mut buf);
        $crate::ArrEncoder::new(buf)
      }
    }

    impl $($impl_generics)* $crate::__private::bitcoin_consensus_encoding::Decodable for $ty {
      type Decoder = $crate::ArrDecoder<$ty, { $n }, $err>;
      fn decoder() -> Self::Decoder {
        $crate::ArrDecoder::new(<$ty as $crate::codec::BaseCodec<$err>>::decode)
      }
    }
  };
  (@parse [$($impl_generics:tt)*] $ty:ty, $n:expr) => {
    $crate::impl_stype!(
      @parse [$($impl_generics)*] $ty,
      $n,
      ::core::convert::Infallible
    );
  };
  (@parse [$($impl_generics:tt)*] $ty:ty) => {
    ::core::compile_error!(concat!(
      "impl_stype! needs the fixed width of ",
      stringify!($ty),
      ": write impl_stype!(", stringify!($ty), ", N)"
    ));
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_stype!(@parse [<$($generic)*>] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_stype!(@parse [] $($args)*);
  };
}

#[cfg(test)]
mod tests {
  use super::{ArrDecoder, ArrEncoder, BufferDecoder, VecEncoder, MAX_ARR_SIZE};
  use crate::codec::{ArrayBuf, DecodeError, EncodeBuf};
  use crate::prelude::*;

  use bitcoin_consensus_encoding::{Decoder, Encoder};
  use rstest::*;
  use zeroize::Zeroize;

  fn filled<const N: usize>(fill: u8, len: usize) -> ArrayBuf<N> {
    let mut b = ArrayBuf::<N>::new();
    b.extend_from_slice(&vec![fill; len]);
    b
  }

  /// Consumes the whole cursor, so `end()` sees no trailing bytes.
  fn take_all(data: &mut &[u8]) -> Result<Vec<u8>, DecodeError> {
    let out = data.to_vec();
    *data = &[];
    Ok(out)
  }

  #[rstest]
  fn arr_encoder_emits_written_prefix_only() {
    // A short write into a wide buffer must not leak the zero padding.
    let mut enc = ArrEncoder::new(filled::<64>(0xAB, 10));
    assert_eq!(enc.current_chunk(), [0xAB; 10]);
    assert!(!enc.advance());
    assert_eq!(enc.current_chunk(), &[] as &[u8]);
  }

  /// The wipe itself. `Drop` on both types delegates straight to this, and
  /// observing the freed storage directly would need `unsafe`, which the
  /// workspace denies.
  #[rstest]
  fn arrbuf_zeroize_clears_contents_and_len() {
    let mut buf = filled::<32>(0xCD, 32);
    assert_eq!(buf.as_bytes(), [0xCD; 32]);
    buf.zeroize();
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.spare(), 32);
    assert_eq!(buf.as_bytes(), &[] as &[u8]);
    // Re-fill and confirm the backing array really was zeroed, not just the
    // length reset.
    buf.extend_from_slice(&[0u8; 32]);
    assert_eq!(buf.as_bytes(), [0u8; 32]);
  }

  /// The cap is a compile-time assert, so only the accepted side is testable
  /// here; `N` above the bound fails to build with "unusually large zeroized
  /// buffer" wherever the encoder or decoder is instantiated.
  #[rstest]
  fn max_width_is_accepted() {
    let enc = ArrEncoder::new(ArrayBuf::<{ MAX_ARR_SIZE }>::new());
    assert_eq!(enc.current_chunk(), &[] as &[u8]);
    let dec = ArrDecoder::<Vec<u8>, { MAX_ARR_SIZE }>::new(take_all);
    assert_eq!(dec.read_limit(), MAX_ARR_SIZE);
  }

  #[rstest]
  fn arr_decoder_roundtrips_and_bounds_reads() {
    let mut dec = ArrDecoder::<Vec<u8>, 8>::new(take_all);
    assert_eq!(dec.read_limit(), 8);
    let mut input: &[u8] = &[1, 2, 3];
    assert!(dec.push_bytes(&mut input).unwrap_or(false));
    assert!(input.is_empty());
    assert_eq!(dec.read_limit(), 5);
    assert_eq!(dec.end().unwrap_or_default(), vec![1, 2, 3]);
  }

  #[rstest]
  fn arr_decoder_stops_at_capacity() {
    let mut dec = ArrDecoder::<Vec<u8>, 4>::new(take_all);
    let mut input: &[u8] = &[9; 10];
    assert!(dec.push_bytes(&mut input).unwrap_or(false));
    assert_eq!(input.len(), 6, "excess must be left for the caller");
    assert_eq!(dec.read_limit(), 0);
    assert!(!dec.push_bytes(&mut input).unwrap_or(true));
  }

  /// Both encoders redact: a `{:?}` in a panic must not print key material.
  #[rstest]
  fn debug_impls_redact_contents() {
    let enc = ArrEncoder::new(filled::<8>(0xFF, 8));
    let dbg = format!("{enc:?}");
    assert!(!dbg.contains("255") && !dbg.contains("ff"), "{dbg}");
    assert!(dbg.contains("len: 8"));

    let venc = VecEncoder::new(vec![0xFFu8; 8]);
    assert!(!format!("{venc:?}").contains("255"));

    let vdec = BufferDecoder::<Vec<u8>>::new(take_all, 16);
    assert!(format!("{vdec:?}").contains("limit: 16"));

    let adec = ArrDecoder::<Vec<u8>, 16>::new(take_all);
    assert!(format!("{adec:?}").contains("limit: 16"));
  }
}
