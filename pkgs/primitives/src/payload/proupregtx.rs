//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use crate::codec::codec_payload;
use crate::prelude::*;
use crate::script::Script;
use crate::validation::{DeploymentContext, ProTxInvalid};
use crate::{InputsHash, TxHash};

use dash_types::{BlsPublicKeyBytes, KeyId};

use core::fmt;

/// ProUpRegTx -- update MN keys/payout (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ProUpRegTx {
  /// 1=LegacyBLS, 2=BasicBLS.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Reserved, always 0.
  pub mode: u16,
  /// Operator BLS public key (48 bytes).
  pub pub_key_operator: BlsPublicKeyBytes,
  /// Voting key id (20 bytes).
  pub key_id_voting: KeyId,
  /// Payout script.
  pub script_payout: Script,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Owner ECDSA signature (variable-length).
  pub vch_sig: Vec<u8>,
}

codec_payload!(ProUpRegTx {
  version,
  pro_tx_hash,
  mode,
  pub_key_operator,
  key_id_voting,
  script_payout,
  inputs_hash,
  vch_sig,
});

impl ProUpRegTx {
  /// Validates structural invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, _ctx: &DeploymentContext) -> Result<(), ProTxInvalid> {
    if self.version == 0 {
      return Err(ProTxInvalid::BadVersion { version: self.version });
    }

    if self.mode != 0 {
      return Err(ProTxInvalid::BadMode { mode: self.mode });
    }

    if self.pub_key_operator.is_null() {
      return Err(ProTxInvalid::NullKey);
    }
    if self.key_id_voting.is_null() {
      return Err(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    if !dash_script::is_p2pkh(payout) && !dash_script::is_p2sh(payout) {
      return Err(ProTxInvalid::BadPayoutScript);
    }

    Ok(())
  }
}

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version)
  }
}
