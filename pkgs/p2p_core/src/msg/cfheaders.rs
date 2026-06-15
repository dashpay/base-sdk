//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter header messages: getcfheaders, cfheaders.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::primitives::FilterType;

use bitcoin_units::BlockHeight;
use dash_primitives::BlockHash;
use dash_types::codec::{BaseCodec, DecodeError};

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

  fn encode(&self, buf: &mut Vec<u8>) {
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
