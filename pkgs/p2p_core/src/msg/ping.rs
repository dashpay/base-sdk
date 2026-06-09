//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ping and Pong keepalive messages.

use crate::codec::codec_p2p;

/// Keepalive request carrying a random nonce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ping {
  /// Random nonce echoed back in the corresponding `Pong`.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
}

codec_p2p!(Ping { nonce });

/// Keepalive response echoing the nonce from a `Ping`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Pong {
  /// Nonce from the original `Ping`.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::str_u64"))]
  pub nonce: u64,
}

codec_p2p!(Pong { nonce });
