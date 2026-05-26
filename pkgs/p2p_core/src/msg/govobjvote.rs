//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance vote message.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::governance::GovernanceVote;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_types::codec::{BaseCodec, DecodeError};

/// A masternode vote on a governance object.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovObjVote {
  /// The vote.
  pub vote: GovernanceVote,
}

impl GovObjVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let vote = <GovernanceVote as BaseCodec>::decode(data)?;
    Ok(Self { vote })
  }
}

impl encoding::Encodable for GovObjVote {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    BaseCodec::encode(&self.vote, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GovObjVote {
  type Decoder = BufferDecoder<GovObjVote, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GovObjVote::decode, MAX_P2P_PAYLOAD)
  }
}
