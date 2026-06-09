//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared validation helpers.
//!
//! Type-specific validation lives in each type's own module. This module
//! provides helpers shared across multiple modules.

use crate::prelude::*;
use crate::support::{NetInfoEntry, NetInfoPurpose};
use crate::tx_types::MnType;

use core::fmt;

/// Maximum serialized transaction size (single tx, always 1 MB).
#[expect(unused, reason = "consensus constant")]
pub(crate) const MAX_LEGACY_BLOCK_SIZE: usize = 1_000_000;

/// Post-DIP0001 maximum block size (2 MB).
pub(crate) const MAX_DIP0001_BLOCK_SIZE: usize = 2_000_000;

/// Maximum extra payload size in bytes.
pub(crate) const MAX_TX_EXTRA_PAYLOAD: usize = 10_000;

/// Number of version bits available for signalling.
pub(crate) const VERSIONBITS_NUM_BITS: u8 = 29;

/// Maximum coinbase script size in bytes.
pub(crate) const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

/// Maximum operator reward in basis points.
pub(crate) const MAX_OPERATOR_REWARD: u16 = 10_000;

/// ProTx version: legacy BLS operator keys (v1).
#[expect(unused, reason = "consensus constant")]
pub(crate) const PROTX_VERSION_LEGACY_BLS: u16 = 1;

/// ProTx version: basic (IETF) BLS operator keys (v2).
pub(crate) const PROTX_VERSION_BASIC_BLS: u16 = 2;

/// ProTx version: extended network addresses (v3).
pub(crate) const PROTX_VERSION_EXT_ADDR: u16 = 3;

/// Provider transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProTxInvalid {
  /// `bad-protx-version`
  BadVersion { version: u16 },
  /// `bad-protx-evo-version`
  EvoVersionTooLow { version: u16 },
  /// `bad-protx-type`
  BadMnType { mn_type: MnType },
  /// `bad-protx-mode`
  BadMode { mode: u16 },
  /// `bad-protx-key-null`
  NullKey,
  /// `bad-protx-operator-pubkey`
  OperatorKeyMismatch,
  /// `bad-protx-payee`
  BadPayoutScript,
  /// `bad-protx-netinfo-version`
  NetInfoVersionMismatch,
  /// `bad-protx-netinfo-empty`
  NetInfoEmpty,
  /// `bad-protx-netinfo-bad`
  NetInfoInvalid,
  /// `bad-protx-payee-reuse`
  PayoutKeyReuse,
  /// `bad-protx-operator-reward`
  OperatorRewardTooHigh { reward: u16 },
  /// `bad-protx-reason`
  BadReason { reason: crate::support::RevocationReason },
}

impl fmt::Display for ProTxInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-protx-version: {version}"),
      Self::EvoVersionTooLow { version } => write!(f, "bad-protx-evo-version: {version}"),
      Self::BadMnType { mn_type } => write!(f, "bad-protx-type: {mn_type}"),
      Self::BadMode { mode } => write!(f, "bad-protx-mode: {mode}"),
      Self::NullKey => write!(f, "bad-protx-key-null"),
      Self::OperatorKeyMismatch => write!(f, "bad-protx-operator-pubkey"),
      Self::BadPayoutScript => write!(f, "bad-protx-payee"),
      Self::NetInfoVersionMismatch => write!(f, "bad-protx-netinfo-version"),
      Self::NetInfoEmpty => write!(f, "bad-protx-netinfo-empty"),
      Self::NetInfoInvalid => write!(f, "bad-protx-netinfo-bad"),
      Self::PayoutKeyReuse => write!(f, "bad-protx-payee-reuse"),
      Self::OperatorRewardTooHigh { reward } => write!(f, "bad-protx-operator-reward: {reward}"),
      Self::BadReason { reason } => write!(f, "bad-protx-reason: {reason}"),
    }
  }
}

/// Checks that an extended net info payload is trivially valid.
pub(crate) fn check_sptx_netinfo(
  entries: &[(NetInfoPurpose, Vec<NetInfoEntry>)],
  mn_type: MnType,
  can_store_platform: bool,
) -> Option<ProTxInvalid> {
  let has_core = entries
    .iter()
    .any(|(p, e)| *p == NetInfoPurpose::CoreP2p && !e.is_empty());
  if !has_core {
    return Some(ProTxInvalid::NetInfoEmpty);
  }

  let has_platform_p2p = entries
    .iter()
    .any(|(p, e)| *p == NetInfoPurpose::PlatformP2p && !e.is_empty());
  let has_platform_https = entries
    .iter()
    .any(|(p, e)| *p == NetInfoPurpose::PlatformHttps && !e.is_empty());

  if mn_type == MnType::Regular && (has_platform_p2p || has_platform_https) {
    return Some(ProTxInvalid::NetInfoInvalid);
  }

  if can_store_platform && mn_type == MnType::Evo && (!has_platform_p2p || !has_platform_https) {
    return Some(ProTxInvalid::NetInfoEmpty);
  }

  for (_purpose, group) in entries {
    for entry in group {
      if matches!(entry, NetInfoEntry::Invalid) {
        return Some(ProTxInvalid::NetInfoInvalid);
      }
    }
  }

  None
}
