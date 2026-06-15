//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P-specific primitive types.

mod command;
mod compressed_header;
mod inventory;
mod magic;
mod mn_list;
mod net_addr;
mod protocol_version;
mod service_flags;
mod short_id;
mod user_agent;

pub use command::CommandString;
pub use compressed_header::CompressionState;
pub use inventory::{InvType, Inventory};
pub use magic::Magic;
pub use mn_list::{DeletedQuorum, GetMnListDiff, MnListDiff, MnListDiffPayload, QuorumClSig, SimplifiedMnListEntry};
pub use net_addr::{AddrV2Entry, NetAddr, TimestampedAddr};
pub use protocol_version::ProtocolVersion;
pub use service_flags::ServiceFlags;
pub use short_id::ShortId;
pub use user_agent::{UserAgent, UserAgentTooLong};
