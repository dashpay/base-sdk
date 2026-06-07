//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object message.

use crate::codec::impl_p2p;
use crate::prelude::*;
use crate::primitives::governance::GovernanceObject;

use dash_types::codec::{BaseCodec, DecodeError};

/// A governance object broadcast or response.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovObj {
  /// The governance object.
  pub object: GovernanceObject,
}

impl BaseCodec for GovObj {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      object: GovernanceObject::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.object.encode(buf);
  }
}

impl_p2p!(GovObj);
