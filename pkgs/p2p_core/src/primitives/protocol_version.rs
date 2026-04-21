//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash protocol version constants.

use core::fmt;

use bitcoin_consensus_encoding as encoding;

/// Protocol version exchanged during the handshake.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
  /// Current protocol version.
  pub const CURRENT: Self = Self(70240);
  /// Minimum acceptable peer version.
  pub const MIN_PEER: Self = Self(70221);
  /// Minimum version for BIP324 v2 transport.
  pub const BIP324_BASELINE: Self = Self(70235);
  /// BLS signature scheme version boundary.
  pub const BLS_SCHEME: Self = Self(70225);
  /// Masternode type field version boundary.
  pub const DMN_TYPE: Self = Self(70227);
  /// Versioned simplified MN list entry boundary.
  pub const SMNLE_VERSIONED: Self = Self(70228);
  /// MN list diff version-first ordering boundary.
  pub const MNLISTDIFF_VERSION_ORDER: Self = Self(70229);
  /// Chainlock signatures in MN list diff boundary.
  pub const MNLISTDIFF_CHAINLOCKS: Self = Self(70230);

  /// Returns the raw `u32` value.
  pub const fn to_u32(self) -> u32 {
    self.0
  }
}

impl fmt::Debug for ProtocolVersion {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProtocolVersion({})", self.0)
  }
}

impl fmt::Display for ProtocolVersion {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}

encoding::encoder_newtype_exact! {
  /// Encoder for [`ProtocolVersion`].
  pub struct ProtocolVersionEncoder<'e>(encoding::ArrayEncoder<4>);
}

impl encoding::Encodable for ProtocolVersion {
  type Encoder<'e> = ProtocolVersionEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    ProtocolVersionEncoder::new(encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes()))
  }
}

/// Decoder for [`ProtocolVersion`].
#[derive(Debug)]
pub struct ProtocolVersionDecoder(encoding::ArrayDecoder<4>);

impl ProtocolVersionDecoder {
  /// Creates a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for ProtocolVersionDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`ProtocolVersion`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolVersionDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for ProtocolVersionDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "protocol version decode: {}", self.0)
  }
}

impl encoding::Decoder for ProtocolVersionDecoder {
  type Output = ProtocolVersion;
  type Error = ProtocolVersionDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(ProtocolVersionDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(ProtocolVersionDecoderError)?;
    Ok(ProtocolVersion(u32::from_le_bytes(buf)))
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for ProtocolVersion {
  type Decoder = ProtocolVersionDecoder;
  fn decoder() -> Self::Decoder {
    ProtocolVersionDecoder::new()
  }
}
