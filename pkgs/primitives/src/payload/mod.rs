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
use crate::tx_types::TxType;
use crate::validation::ProTxInvalid;

use dash_types::codec::Checkable;

use core::fmt;

pub use assetlock::{AssetLock, AssetLockInvalid};
pub use assetunlock::{AssetUnlock, AssetUnlockInvalid};
pub use cbtx::{CbTxInvalid, CoinbaseCommitment};
pub use mnhftx::{MnHardFork, MnHardForkInvalid};
pub use proregtx::{NetInfo, ProRegTx};
pub use proupregtx::ProUpRegTx;
pub use prouprevtx::ProUpRevTx;
pub use proupservtx::ProUpServTx;
pub use quorum::{Commitment, CommitmentInvalid, FinalCommitment};

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
