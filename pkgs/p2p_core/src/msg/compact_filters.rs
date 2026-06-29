//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact block filter types and messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use bitcoin_units::BlockHeight;
use dash_primitives::BlockHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};

dash_types::make_num! {
  /// BIP157 filter type, encoded as a single byte on the wire.
  FilterType, u8, 1
}

impl FilterType {
  /// Basic filter (the only type defined by BIP158).
  pub const BASIC: Self = Self(0);
}

/// Requests compact filters for a range of blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFilters {
  /// Filter type (0 = basic).
  pub filter_type: FilterType,
  /// Start height (inclusive).
  pub start_height: BlockHeight,
  /// Stop block hash (inclusive).
  pub stop_hash: BlockHash,
}

impl_p2p!(GetCFilters);

impl BaseCodec for GetCFilters {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: FilterType(u8::decode(data)?),
      start_height: BlockHeight::from_u32(u32::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.0.encode(buf);
    self.start_height.to_u32().encode(buf);
    self.stop_hash.encode(buf);
  }
}

/// A single compact block filter.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFilter {
  /// Filter type.
  pub filter_type: FilterType,
  /// Block hash this filter covers.
  pub block_hash: BlockHash,
  /// Raw GCS filter data.
  pub filter_data: Vec<u8>,
}

codec_p2p!(CFilter {
  filter_type,
  block_hash,
  filter_data
});

/// Requests compact filter headers for a range of blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFHeaders {
  /// Filter type.
  pub filter_type: FilterType,
  /// Start height (inclusive).
  pub start_height: BlockHeight,
  /// Stop block hash (inclusive).
  pub stop_hash: BlockHash,
}

impl_p2p!(GetCFHeaders);

impl BaseCodec for GetCFHeaders {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: FilterType(u8::decode(data)?),
      start_height: BlockHeight::from_u32(u32::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.filter_type.0.encode(buf);
    self.start_height.to_u32().encode(buf);
    self.stop_hash.encode(buf);
  }
}

/// Response carrying filter headers and their hashes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFHeaders {
  /// Filter type.
  pub filter_type: FilterType,
  /// Hash of the stop block.
  pub stop_hash: BlockHash,
  /// Previous filter header (for chaining).
  pub previous_filter_header: BlockHash,
  /// Filter hashes in block-height order.
  pub filter_hashes: Vec<BlockHash>,
}

codec_p2p!(CFHeaders {
  filter_type,
  stop_hash,
  previous_filter_header,
  filter_hashes,
});

/// Requests evenly-spaced compact filter checkpoints.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
}

codec_p2p!(GetCFCheckpt { filter_type, stop_hash });

/// Response carrying filter header checkpoints at 1000-block intervals.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
  /// Filter headers at every 1000th block.
  pub filter_headers: Vec<BlockHash>,
}

codec_p2p!(CFCheckpt {
  filter_type,
  stop_hash,
  filter_headers
});
