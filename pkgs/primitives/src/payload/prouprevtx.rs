//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRevTx revocation payload (type 4).

use crate::codec::codec_payload;
use crate::support::RevocationReason;
use crate::validation::{DeploymentContext, ProTxInvalid};
use crate::{InputsHash, TxHash};

use dash_types::BlsSignatureBytes;

use core::fmt;

/// ProUpRevTx -- revoke a masternode (type 4).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ProUpRevTx {
  /// 1=LegacyBLS, 2=BasicBLS.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Revocation reason.
  pub reason: RevocationReason,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Operator BLS signature.
  pub sig: BlsSignatureBytes,
}

codec_payload!(ProUpRevTx {
  version,
  pro_tx_hash,
  reason,
  inputs_hash,
  sig,
});

impl ProUpRevTx {
  /// Validates structural invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, _ctx: &DeploymentContext) -> Result<(), ProTxInvalid> {
    if self.version == 0 {
      return Err(ProTxInvalid::BadVersion { version: self.version });
    }

    if matches!(self.reason, RevocationReason::Unknown(_)) {
      return Err(ProTxInvalid::BadReason { reason: self.reason });
    }

    Ok(())
  }
}

impl fmt::Display for ProUpRevTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRevTx {{ v{} }}", self.version)
  }
}
