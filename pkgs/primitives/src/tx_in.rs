//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction input.

use crate::codec_type;
use crate::outpoint::OutPoint;
use crate::script::Script;

use core::fmt;

/// A transaction input.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxIn {
  /// The outpoint being spent.
  pub prevout: OutPoint,
  /// Unlocking script.
  pub script_sig: Script,
  /// Sequence number.
  pub sequence: u32,
}

codec_type!(TxIn {
  prevout,
  script_sig,
  sequence
});

impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxIn {{ prevout: {}, seq: {} }}", self.prevout, self.sequence,)
  }
}
