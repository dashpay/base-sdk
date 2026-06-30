//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash P2P message types for BIP324 encrypted transport.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod codec;
mod error;
mod msg;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod primitives;
mod v2;

#[doc(hidden)]
pub mod __private {
  pub use dash_primitives;
  pub use dash_types;
}

pub use error::P2pDecodeError;
pub use msg::{
  Addr, AddrV2Entry, AddrV2Msg, CFCheckpt, CFHeaders, CFilter, DashNetworkMessage, FilterType, GetCFCheckpt,
  GetCFHeaders, GetCFilters, GetData, GetHeaders, GetHeaders2, GovSync, Headers, Headers2, Inv, NotFound, Ping, Pong,
  TimestampedAddr, Version, VersionAddr,
};
pub use primitives::{
  CommandString, CompressionState, DeletedQuorum, GetMnListDiff, InvType, Inventory, Magic, MnListDiff,
  MnListDiffPayload, ProtocolVersion, QuorumClSig, ServiceFlags, ShortId, SimplifiedMnListEntry, UserAgent,
  UserAgentTooLong,
};
pub use v2::{decode_v2, encode_v2};
