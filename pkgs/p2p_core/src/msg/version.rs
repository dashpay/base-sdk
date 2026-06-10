//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version handshake message (Dash-extended).

use crate::codec::codec_p2p;
use crate::primitives::net_addr::NetAddr;
use crate::primitives::protocol_version::ProtocolVersion;
use crate::primitives::service_flags::ServiceFlags;
use crate::primitives::user_agent::UserAgent;

use dash_num::Hash256;

/// The `version` message initiates the P2P handshake.
///
/// Dash extends the Bitcoin version message with two additional
/// fields for masternode authentication.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Version {
  /// Sender's protocol version.
  pub protocol_version: ProtocolVersion,
  /// Sender's advertised services.
  pub services: ServiceFlags,
  /// Unix timestamp of the sender.
  pub timestamp: i64,
  /// Receiver's address as seen by the sender.
  pub addr_recv: NetAddr,
  /// Sender's own address.
  pub addr_send: NetAddr,
  /// Random nonce for connection deduplication.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
  /// User agent string.
  pub user_agent: UserAgent,
  /// Sender's best block height.
  pub start_height: i32,
  /// Whether the sender wants transaction relay.
  pub relay: bool,
  /// Dash: masternode authentication challenge.
  pub mnauth_challenge: Hash256,
  /// Dash: whether the sender identifies as a masternode.
  pub mn_connection: bool,
}

codec_p2p!(Version {
  protocol_version,
  services,
  timestamp,
  addr_recv,
  addr_send,
  nonce,
  user_agent,
  start_height,
  relay,
  mnauth_challenge,
  mn_connection,
});

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, load_corpus_file, read_corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_version() {
    let text = load_corpus_file(env!("CARGO_MANIFEST_DIR"), "version");
    let items = read_corpus::<Version>(&text, "version", check_wire);
    assert_serde_rt("version", &items);
  }
}
