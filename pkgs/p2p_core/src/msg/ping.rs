//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ping and Pong keepalive messages.

use crate::codec::impl_p2p;
use crate::prelude::*;

use dash_types::codec::{BaseCodec, DecodeError};

/// Keepalive request carrying a random nonce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ping {
  /// Random nonce echoed back in the corresponding `Pong`.
  pub nonce: u64,
}

impl BaseCodec for Ping {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      nonce: u64::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.nonce.encode(buf);
  }
}

impl_p2p!(Ping);

/// Keepalive response echoing the nonce from a `Ping`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Pong {
  /// Nonce from the original `Ping`.
  pub nonce: u64,
}

impl BaseCodec for Pong {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      nonce: u64::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.nonce.encode(buf);
  }
}

impl_p2p!(Pong);
