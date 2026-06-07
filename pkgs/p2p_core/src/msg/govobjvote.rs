//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance vote message.

use crate::codec::impl_p2p;
use crate::prelude::*;
use crate::primitives::governance::GovernanceVote;

use dash_types::codec::{BaseCodec, DecodeError};

/// A masternode vote on a governance object.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovObjVote {
  /// The vote.
  pub vote: GovernanceVote,
}

impl BaseCodec for GovObjVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      vote: GovernanceVote::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.vote.encode(buf);
  }
}

impl_p2p!(GovObjVote);
