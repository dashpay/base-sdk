//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Special transaction payload decoders.
//!
//! Each payload type is decoded from the `extra_payload` field of a
//! `Transaction` whose `tx_type` is not `Spend`.

mod assetlock;
mod assetunlock;
mod cbtx;
mod mnhftx;
mod proregtx;
mod proupregtx;
mod prouprevtx;
mod proupservtx;
mod quorum;

use crate::prelude::*;
use crate::types::{NIError, NIPurpose, NITrait, NetInfoV2};

use dash_num::{make_hash, Hash256};
use dash_types::codec::{Checkable, NumCodec};
use dash_types::impl_num;

use core::fmt;

/// Maximum operator reward in basis points.
pub(crate) const MAX_OPERATOR_REWARD: u16 = 10_000;

/// ProTx version: legacy BLS operator keys (v1).
#[expect(unused, reason = "consensus constant")]
pub(crate) const PROTX_VERSION_LEGACY_BLS: u16 = 1;

/// ProTx version: basic (IETF) BLS operator keys (v2).
pub(crate) const PROTX_VERSION_BASIC_BLS: u16 = 2;

/// ProTx version: extended network addresses (v3).
pub(crate) const PROTX_VERSION_EXT_ADDR: u16 = 3;

make_hash! {
  Hash256,
  /// LLMQ quorum identifier.
  QuorumHash
}

make_hash! {
  Hash256,
  /// Hash of serialized transaction inputs.
  InputsHash
}

/// Dash transaction type, encoded in the upper 16 bits of the version field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TxType {
  /// Spend transaction (includes legacy coinbase).
  Spend,
  /// Masternode registration (type 1).
  ProviderRegister,
  /// Masternode service address update (type 2).
  ProviderUpdateService,
  /// Masternode registrar key update (type 3).
  ProviderUpdateRegistrar,
  /// Masternode revocation (type 4).
  ProviderUpdateRevoke,
  /// Coinbase commitment special transaction (type 5).
  CoinbaseCommitment,
  /// LLMQ final commitment (type 6).
  QuorumCommitment,
  /// Masternode hard fork signal (type 7).
  MnhfSignal,
  /// Asset lock: L1 to platform (type 8).
  AssetLock,
  /// Asset unlock: platform to L1 (type 9).
  AssetUnlock,
  /// Unknown or future transaction type.
  Unknown(u16),
}

impl NumCodec<u16> for TxType {
  fn from_base(value: u16) -> Self {
    match value {
      0 => Self::Spend,
      1 => Self::ProviderRegister,
      2 => Self::ProviderUpdateService,
      3 => Self::ProviderUpdateRegistrar,
      4 => Self::ProviderUpdateRevoke,
      5 => Self::CoinbaseCommitment,
      6 => Self::QuorumCommitment,
      7 => Self::MnhfSignal,
      8 => Self::AssetLock,
      9 => Self::AssetUnlock,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u16 {
    match self {
      Self::Spend => 0,
      Self::ProviderRegister => 1,
      Self::ProviderUpdateService => 2,
      Self::ProviderUpdateRegistrar => 3,
      Self::ProviderUpdateRevoke => 4,
      Self::CoinbaseCommitment => 5,
      Self::QuorumCommitment => 6,
      Self::MnhfSignal => 7,
      Self::AssetLock => 8,
      Self::AssetUnlock => 9,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(TxType, u16);

impl fmt::Display for TxType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Spend => write!(f, "spend"),
      Self::ProviderRegister => write!(f, "provider_register"),
      Self::ProviderUpdateService => write!(f, "provider_update_service"),
      Self::ProviderUpdateRegistrar => write!(f, "provider_update_registrar"),
      Self::ProviderUpdateRevoke => write!(f, "provider_update_revoke"),
      Self::CoinbaseCommitment => write!(f, "coinbase_commitment"),
      Self::QuorumCommitment => write!(f, "quorum_commitment"),
      Self::MnhfSignal => write!(f, "mnhf_signal"),
      Self::AssetLock => write!(f, "asset_lock"),
      Self::AssetUnlock => write!(f, "asset_unlock"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// Masternode type, used in provider registration and update transactions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MnType {
  /// Regular masternode.
  Regular,
  /// Evolution (Evo) masternode with platform capabilities.
  Evo,
  /// Unknown or future masternode type.
  Unknown(u16),
}

impl NumCodec<u16> for MnType {
  fn from_base(value: u16) -> Self {
    match value {
      0 => Self::Regular,
      1 => Self::Evo,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u16 {
    match self {
      Self::Regular => 0,
      Self::Evo => 1,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(MnType, u16);

impl fmt::Display for MnType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Regular => write!(f, "regular"),
      Self::Evo => write!(f, "evo"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

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
  NetInfoInvalid {
    /// The underlying error.
    error: NIError,
  },
  /// `bad-protx-payee-reuse`
  PayoutKeyReuse,
  /// `bad-protx-operator-reward`
  OperatorRewardTooHigh { reward: u16 },
  /// `bad-protx-reason`
  BadReason { reason: crate::support::RevocationReason },
  /// `bad-protx-platform-fields`
  BadPlatformFields,
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
      Self::NetInfoInvalid { error } => write!(f, "bad-protx-netinfo-bad: {error}"),
      Self::PayoutKeyReuse => write!(f, "bad-protx-payee-reuse"),
      Self::OperatorRewardTooHigh { reward } => write!(f, "bad-protx-operator-reward: {reward}"),
      Self::BadReason { reason } => write!(f, "bad-protx-reason: {reason}"),
      Self::BadPlatformFields => write!(f, "bad-protx-platform-fields"),
    }
  }
}

/// Checks that an extended net info payload is trivially valid.
pub(crate) fn check_sptx_netinfo(ext: &NetInfoV2, version: u16, mn_type: MnType) -> Option<ProTxInvalid> {
  if let Some(error) = ext.check() {
    return Some(ProTxInvalid::NetInfoInvalid { error });
  }
  if !ext.has_entries(NIPurpose::CoreP2p) {
    return Some(ProTxInvalid::NetInfoEmpty);
  }
  if mn_type == MnType::Regular
    && (ext.has_entries(NIPurpose::PlatformP2p) || ext.has_entries(NIPurpose::PlatformHttps))
  {
    return Some(ProTxInvalid::NetInfoInvalid {
      error: NIError::Malformed,
    });
  }
  if version >= PROTX_VERSION_EXT_ADDR
    && mn_type == MnType::Evo
    && (!ext.has_entries(NIPurpose::PlatformP2p) || !ext.has_entries(NIPurpose::PlatformHttps))
  {
    return Some(ProTxInvalid::NetInfoEmpty);
  }
  None
}

pub use assetlock::{AssetLock, AssetLockInvalid};
pub use assetunlock::{AssetUnlock, AssetUnlockInvalid};
pub use cbtx::{CbTxInvalid, CoinbaseCommitment};
pub use mnhftx::{MnHardFork, MnHardForkInvalid, VERSIONBITS_NUM_BITS};
pub use proregtx::{PlatformNodeId, ProRegTx};
pub use proupregtx::ProUpRegTx;
pub use prouprevtx::ProUpRevTx;
pub use proupservtx::ProUpServTx;
pub use quorum::{Commitment, CommitmentInvalid, FinalCommitment, QuorumVvecHash};

/// A decoded special transaction payload.
///
/// Provides a unified dispatch over all Dash special transaction types. Unknown
/// or future types are stored as opaque bytes for forward compatibility.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum SpecialPayload {
  /// Masternode registration (type 1).
  ProviderRegister(ProRegTx),
  /// Masternode service update (type 2).
  ProviderUpdateService(ProUpServTx),
  /// Masternode registrar update (type 3).
  ProviderUpdateRegistrar(ProUpRegTx),
  /// Masternode revocation (type 4).
  ProviderUpdateRevoke(ProUpRevTx),
  /// Coinbase commitment (type 5).
  CoinbaseCommitment(CoinbaseCommitment),
  /// LLMQ final commitment (type 6).
  QuorumCommitment(FinalCommitment),
  /// Hard-fork signal (type 7).
  MnhfSignal(MnHardFork),
  /// Asset lock: L1 to Platform (type 8).
  AssetLock(AssetLock),
  /// Asset unlock: Platform to L1 (type 9).
  AssetUnlock(AssetUnlock),
  /// Unrecognized type, stored as raw bytes.
  Unknown {
    /// The transaction type code.
    tx_type: TxType,
    /// The raw extra payload bytes.
    data: Vec<u8>,
  },
}

/// Error decoding a special payload.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PayloadError {
  /// Which transaction type was being decoded.
  pub tx_type: TxType,
  /// Human-readable description.
  pub message: String,
}

impl fmt::Display for PayloadError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{} payload: {}", self.tx_type, self.message)
  }
}

/// Structural check failure for a special payload.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PayloadInvalid {
  /// Provider transaction check failed.
  ProTx(ProTxInvalid),
  /// Coinbase commitment check failed.
  CbTx(CbTxInvalid),
  /// Hard-fork signal check failed.
  MnHardFork(MnHardForkInvalid),
  /// Asset lock check failed.
  AssetLock(AssetLockInvalid),
  /// Asset unlock check failed.
  AssetUnlock(AssetUnlockInvalid),
  /// Quorum commitment check failed.
  Commitment(CommitmentInvalid),
}

impl fmt::Display for PayloadInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ProTx(e) => e.fmt(f),
      Self::CbTx(e) => e.fmt(f),
      Self::MnHardFork(e) => e.fmt(f),
      Self::AssetLock(e) => e.fmt(f),
      Self::AssetUnlock(e) => e.fmt(f),
      Self::Commitment(e) => e.fmt(f),
    }
  }
}

impl Checkable for SpecialPayload {
  type Error = PayloadInvalid;

  fn check(&self) -> Option<Self::Error> {
    match self {
      Self::ProviderRegister(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateService(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateRegistrar(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateRevoke(p) => p.check().map(PayloadInvalid::ProTx),
      Self::CoinbaseCommitment(p) => p.check().map(PayloadInvalid::CbTx),
      Self::QuorumCommitment(p) => p.check().map(PayloadInvalid::Commitment),
      Self::MnhfSignal(p) => p.check().map(PayloadInvalid::MnHardFork),
      Self::AssetLock(p) => p.check().map(PayloadInvalid::AssetLock),
      Self::AssetUnlock(p) => p.check().map(PayloadInvalid::AssetUnlock),
      Self::Unknown { .. } => None,
    }
  }
}

impl SpecialPayload {
  /// Decodes a payload from its transaction type and raw bytes.
  ///
  /// Returns `Unknown` for unrecognized types rather than an error, ensuring
  /// forward compatibility with future transaction types.
  ///
  /// # Errors
  ///
  /// Returns `PayloadError` if a recognized type fails to decode.
  pub fn decode(tx_type: TxType, data: &mut &[u8]) -> Result<Self, PayloadError> {
    use dash_types::codec::{BaseCodec, DecodeError};

    let err = |e: DecodeError| PayloadError {
      tx_type,
      message: format!("{e}"),
    };
    match tx_type {
      TxType::Spend => Err(PayloadError {
        tx_type,
        message: String::from("spend transactions have no payload"),
      }),
      TxType::ProviderRegister => ProRegTx::decode(data).map(Self::ProviderRegister).map_err(err),
      TxType::ProviderUpdateService => ProUpServTx::decode(data).map(Self::ProviderUpdateService).map_err(err),
      TxType::ProviderUpdateRegistrar => ProUpRegTx::decode(data).map(Self::ProviderUpdateRegistrar).map_err(err),
      TxType::ProviderUpdateRevoke => ProUpRevTx::decode(data).map(Self::ProviderUpdateRevoke).map_err(err),
      TxType::CoinbaseCommitment => cbtx::CoinbaseCommitment::decode(data)
        .map(Self::CoinbaseCommitment)
        .map_err(err),
      TxType::QuorumCommitment => FinalCommitment::decode(data).map(Self::QuorumCommitment).map_err(err),
      TxType::MnhfSignal => MnHardFork::decode(data).map(Self::MnhfSignal).map_err(err),
      TxType::AssetLock => assetlock::AssetLock::decode(data).map(Self::AssetLock).map_err(err),
      TxType::AssetUnlock => assetunlock::AssetUnlock::decode(data)
        .map(Self::AssetUnlock)
        .map_err(err),
      unknown => {
        let bytes = data.to_vec();
        *data = &[];
        Ok(Self::Unknown {
          tx_type: unknown,
          data: bytes,
        })
      }
    }
  }
}
