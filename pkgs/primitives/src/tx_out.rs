//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction output.

use crate::prelude::*;
use crate::script::Script;

use bitcoin_units::Amount;
use dash_types::codec::{BaseCodec, DecodeError};
use dash_types::impl_type;

use core::fmt;

/// A transaction output.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TxOut {
  /// Output value in duffs.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::amount"))]
  pub value: Amount,
  /// Locking script.
  pub script_pubkey: Script,
}

impl_type!(TxOut);

impl BaseCodec for TxOut {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = u64::decode(data)?;
    let value = Amount::from_sat(raw).map_err(|_| DecodeError::InvalidValue {
      expected: Amount::MAX_MONEY.to_sat(),
      actual: raw,
    })?;
    Ok(Self {
      value,
      script_pubkey: Script::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.value.to_sat().encode(buf);
    self.script_pubkey.encode(buf);
  }
}

impl fmt::Display for TxOut {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxOut {{ value: {} }}", self.value.to_sat())
  }
}
