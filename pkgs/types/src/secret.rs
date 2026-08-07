//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Secret-holding codec implementation.

use crate::codec::{DecodeError, EncodeBuf};

use bitcoin_consensus_encoding::{Decoder, Encoder};
use zeroize::Zeroize;

use core::convert::Infallible;
use core::fmt;

/// Widest buffer [`ArrEncoder`] and [`ArrDecoder`] will wipe.
pub const MAX_ARR_SIZE: usize = 512;

/// Fixed-size encode buffer backed by `[u8; N]`.
///
/// # Panics
///
/// Writing more than `N` bytes (via the [`EncodeBuf`] impl) panics with an
/// index-out-of-bounds.
#[derive(Clone)]
pub struct ArrayBuf<const N: usize> {
  buf: [u8; N],
  len: usize,
}

impl<const N: usize> ArrayBuf<N> {
  /// Creates an empty buffer.
  pub const fn new() -> Self {
    Self { buf: [0u8; N], len: 0 }
  }

  /// Borrows the written bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.buf[..self.len]
  }

  /// Returns `true` when nothing has been written.
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// Number of bytes written so far.
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Remaining writable capacity.
  pub const fn spare(&self) -> usize {
    N - self.len
  }

  /// Returns the written bytes as a fixed array.
  ///
  /// # Panics
  ///
  /// Panics if exactly `N` bytes were not written.
  pub fn into_array(self) -> [u8; N] {
    assert!(self.len == N, "expected {N} bytes, wrote {}", self.len);
    self.buf
  }
}

impl<const N: usize> fmt::Debug for ArrayBuf<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ArrayBuf").field("len", &self.len).finish()
  }
}

impl<const N: usize> Default for ArrayBuf<N> {
  fn default() -> Self {
    Self::new()
  }
}

impl<const N: usize> EncodeBuf for ArrayBuf<N> {
  fn push(&mut self, byte: u8) {
    self.buf[self.len] = byte;
    self.len += 1;
  }

  fn extend_from_slice(&mut self, data: &[u8]) {
    self.buf[self.len..self.len + data.len()].copy_from_slice(data);
    self.len += data.len();
  }
}

impl<const N: usize> Zeroize for ArrayBuf<N> {
  fn zeroize(&mut self) {
    self.buf.zeroize();
    self.len = 0;
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

/// Generates `Encodable` + `Decodable` for a `BaseCodec` implementor whose
/// wire image is secret.
#[macro_export]
macro_rules! impl_stype {
  (@parse [$($impl_generics:tt)*] $ty:ty, $n:expr, $err:ty) => {
    impl $($impl_generics)* $crate::__private::bitcoin_consensus_encoding::Encodable for $ty {
      type Encoder<'e> = $crate::ArrEncoder<{ $n }>;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = $crate::ArrayBuf::<{ $n }>::new();
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
      "impl_stype! needs the fixed width of ", stringify!($ty), ": write impl_stype!(", stringify!($ty), ", N)"
    ));
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_stype!(@parse [<$($generic)*>] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_stype!(@parse [] $($args)*);
  };
}

/// Generates the consensus encoding traits for a fixed-size byte newtype with
/// secret contents.
#[macro_export]
macro_rules! impl_sbytes {
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

    $crate::impl_stype!($name, $n);

    impl From<[u8; $n]> for $name {
      fn from(bytes: [u8; $n]) -> Self { Self(bytes) }
    }
  )* };
}

#[cfg(test)]
mod tests {
  use super::{ArrDecoder, ArrEncoder, ArrayBuf, MAX_ARR_SIZE};
  use crate::codec::{DecodeError, EncodeBuf};
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

    let adec = ArrDecoder::<Vec<u8>, 16>::new(take_all);
    assert!(format!("{adec:?}").contains("limit: 16"));
  }
}
