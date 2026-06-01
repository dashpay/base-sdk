//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction input.

use crate::outpoint::OutPoint;
use crate::prelude::*;
use crate::script::Script;

use dash_types::codec::{self, BaseCodec, DecodeError};
use dash_types::impl_type;

use core::fmt;

/// A transaction input.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TxIn {
  /// The outpoint being spent.
  pub prevout: OutPoint,
  /// Unlocking script.
  pub script_sig: Script,
  /// Sequence number.
  pub sequence: u32,
}

impl BaseCodec for TxIn {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let prevout = OutPoint::decode(data)?;
    let script_sig = Script::decode(data)?;
    let sequence = codec::read_u32_le(data)?;
    Ok(Self {
      prevout,
      script_sig,
      sequence,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.prevout.encode(buf);
    self.script_sig.encode(buf);
    buf.extend_from_slice(&self.sequence.to_le_bytes());
  }
}

impl_type!(TxIn);

impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxIn {{ prevout: {}, seq: {} }}", self.prevout, self.sequence,)
  }
}
