//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter messages: getcfilters, cfilter.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_units::BlockHeight;
use dash_primitives::BlockHash;
use dash_types::codec::{BaseCodec, DecodeError};

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

  fn encode(&self, buf: &mut Vec<u8>) {
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
