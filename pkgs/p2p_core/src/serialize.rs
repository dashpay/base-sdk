//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

use crate::prelude::*;

use bitcoin_primitives::BlockHash;
use bitcoin_units::BlockHeight;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// For [`BlockHash`](bitcoin_primitives::BlockHash) as a hex string.
mod block_hash {
  use super::*;

  pub fn serialize<S: Serializer>(val: &BlockHash, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&alloc::format!("{val}"))
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BlockHash, D::Error> {
    let s = <Cow<'_, str>>::deserialize(d)?;
    s.parse().map_err(::serde::de::Error::custom)
  }
}

/// For [`BlockHeight`](bitcoin_units::BlockHeight) as `u32`.
mod block_height {
  use super::*;

  pub fn serialize<S: Serializer>(val: &BlockHeight, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u32(val.to_u32())
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BlockHeight, D::Error> {
    Ok(BlockHeight::from_u32(u32::deserialize(d)?))
  }
}

/// For [`GetCFilters`](bitcoin_p2p_messages::message_filter::GetCFilters).
pub mod get_cfilters {
  use super::*;

  use bitcoin_p2p_messages::message_filter::GetCFilters;

  pub fn serialize<S: Serializer>(val: &GetCFilters, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ser {
      filter_type: u8,
      #[serde(with = "super::block_height")]
      start_height: BlockHeight,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
    }
    Ser {
      filter_type: val.filter_type,
      start_height: val.start_height,
      stop_hash: val.stop_hash,
    }
    .serialize(s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<GetCFilters, D::Error> {
    #[derive(Deserialize)]
    struct De {
      filter_type: u8,
      #[serde(with = "super::block_height")]
      start_height: BlockHeight,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
    }
    let r = De::deserialize(d)?;
    Ok(GetCFilters {
      filter_type: r.filter_type,
      start_height: r.start_height,
      stop_hash: r.stop_hash,
    })
  }
}

/// For [`CFilter`](bitcoin_p2p_messages::message_filter::CFilter).
pub mod cfilter {
  use super::*;

  use bitcoin_p2p_messages::message_filter::CFilter;

  pub fn serialize<S: Serializer>(val: &CFilter, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ser<'a> {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      block_hash: BlockHash,
      filter: &'a [u8],
    }
    Ser {
      filter_type: val.filter_type,
      block_hash: val.block_hash,
      filter: &val.filter,
    }
    .serialize(s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<CFilter, D::Error> {
    #[derive(Deserialize)]
    struct De {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      block_hash: BlockHash,
      filter: Vec<u8>,
    }
    let r = De::deserialize(d)?;
    Ok(CFilter {
      filter_type: r.filter_type,
      block_hash: r.block_hash,
      filter: r.filter,
    })
  }
}

/// For [`GetCFHeaders`](bitcoin_p2p_messages::message_filter::GetCFHeaders).
pub mod get_cfheaders {
  use super::*;

  use bitcoin_p2p_messages::message_filter::GetCFHeaders;

  pub fn serialize<S: Serializer>(val: &GetCFHeaders, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ser {
      filter_type: u8,
      #[serde(with = "super::block_height")]
      start_height: BlockHeight,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
    }
    Ser {
      filter_type: val.filter_type,
      start_height: val.start_height,
      stop_hash: val.stop_hash,
    }
    .serialize(s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<GetCFHeaders, D::Error> {
    #[derive(Deserialize)]
    struct De {
      filter_type: u8,
      #[serde(with = "super::block_height")]
      start_height: BlockHeight,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
    }
    let r = De::deserialize(d)?;
    Ok(GetCFHeaders {
      filter_type: r.filter_type,
      start_height: r.start_height,
      stop_hash: r.stop_hash,
    })
  }
}

/// For [`CFHeaders`](bitcoin_p2p_messages::message_filter::CFHeaders).
pub mod cfheaders {
  use super::*;

  use bitcoin_p2p_messages::message_filter::{CFHeaders, FilterHash, FilterHeader};

  pub fn serialize<S: Serializer>(val: &CFHeaders, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ser<'a> {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
      previous_filter_header: FilterHeader,
      filter_hashes: &'a [FilterHash],
    }
    Ser {
      filter_type: val.filter_type,
      stop_hash: val.stop_hash,
      previous_filter_header: val.previous_filter_header,
      filter_hashes: &val.filter_hashes,
    }
    .serialize(s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<CFHeaders, D::Error> {
    #[derive(Deserialize)]
    struct De {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
      previous_filter_header: FilterHeader,
      filter_hashes: Vec<FilterHash>,
    }
    let r = De::deserialize(d)?;
    Ok(CFHeaders {
      filter_type: r.filter_type,
      stop_hash: r.stop_hash,
      previous_filter_header: r.previous_filter_header,
      filter_hashes: r.filter_hashes,
    })
  }
}

/// For [`GetCFCheckpt`](bitcoin_p2p_messages::message_filter::GetCFCheckpt).
pub mod get_cfcheckpt {
  use super::*;

  use bitcoin_p2p_messages::message_filter::GetCFCheckpt;

  pub fn serialize<S: Serializer>(val: &GetCFCheckpt, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ser {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
    }
    Ser {
      filter_type: val.filter_type,
      stop_hash: val.stop_hash,
    }
    .serialize(s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<GetCFCheckpt, D::Error> {
    #[derive(Deserialize)]
    struct De {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
    }
    let r = De::deserialize(d)?;
    Ok(GetCFCheckpt {
      filter_type: r.filter_type,
      stop_hash: r.stop_hash,
    })
  }
}

/// For [`SendCmpct`](bitcoin_p2p_messages::message_compact_blocks::SendCmpct).
pub mod send_cmpct {
  use super::*;

  use bitcoin_p2p_messages::message_compact_blocks::SendCmpct;

  pub fn serialize<S: Serializer>(val: &SendCmpct, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ser {
      send_compact: bool,
      version: u64,
    }
    Ser {
      send_compact: val.send_compact,
      version: val.version,
    }
    .serialize(s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SendCmpct, D::Error> {
    #[derive(Deserialize)]
    struct De {
      send_compact: bool,
      version: u64,
    }
    let r = De::deserialize(d)?;
    Ok(SendCmpct {
      send_compact: r.send_compact,
      version: r.version,
    })
  }
}

/// For [`CFCheckpt`](bitcoin_p2p_messages::message_filter::CFCheckpt).
pub mod cfcheckpt {
  use super::*;

  use bitcoin_p2p_messages::message_filter::{CFCheckpt, FilterHeader};

  pub fn serialize<S: Serializer>(val: &CFCheckpt, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Ser<'a> {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
      filter_headers: &'a [FilterHeader],
    }
    Ser {
      filter_type: val.filter_type,
      stop_hash: val.stop_hash,
      filter_headers: &val.filter_headers,
    }
    .serialize(s)
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<CFCheckpt, D::Error> {
    #[derive(Deserialize)]
    struct De {
      filter_type: u8,
      #[serde(with = "super::block_hash")]
      stop_hash: BlockHash,
      filter_headers: Vec<FilterHeader>,
    }
    let r = De::deserialize(d)?;
    Ok(CFCheckpt {
      filter_type: r.filter_type,
      stop_hash: r.stop_hash,
      filter_headers: r.filter_headers,
    })
  }
}
