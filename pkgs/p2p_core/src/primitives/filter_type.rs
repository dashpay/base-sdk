//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compact block filter type identifier.

use core::fmt;

use bitcoin_consensus_encoding as encoding;

/// BIP157 filter type, encoded as a single byte on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FilterType(pub u8);

impl FilterType {
  /// Basic filter (the only type defined by BIP158).
  pub const BASIC: Self = Self(0);

  /// Returns the raw byte.
  pub const fn to_u8(self) -> u8 {
    self.0
  }
}

impl From<u8> for FilterType {
  fn from(v: u8) -> Self {
    Self(v)
  }
}

impl fmt::Debug for FilterType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "FilterType({})", self.0)
  }
}

impl fmt::Display for FilterType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

encoding::encoder_newtype_exact! {
  /// Encoder for [`FilterType`].
  pub struct FilterTypeEncoder<'e>(encoding::ArrayEncoder<1>);
}

impl encoding::Encodable for FilterType {
  type Encoder<'e> = FilterTypeEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    FilterTypeEncoder::new(encoding::ArrayEncoder::without_length_prefix([self.0]))
  }
}

/// Decoder for [`FilterType`].
#[derive(Debug)]
pub struct FilterTypeDecoder(encoding::ArrayDecoder<1>);

impl FilterTypeDecoder {
  /// Creates a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for FilterTypeDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`FilterType`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterTypeDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for FilterTypeDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "filter type decode: {}", self.0)
  }
}

impl encoding::Decoder for FilterTypeDecoder {
  type Output = FilterType;
  type Error = FilterTypeDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(FilterTypeDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(FilterTypeDecoderError)?;
    Ok(FilterType(buf[0]))
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for FilterType {
  type Decoder = FilterTypeDecoder;
  fn decoder() -> Self::Decoder {
    FilterTypeDecoder::new()
  }
}
