//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash primitive types for consensus encoding and decoding.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod block;
mod block_header;
mod codec;
mod gov;
mod hash;
mod outpoint;
mod payload;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod script;
mod support;
mod transaction;
mod tx_in;
mod tx_out;

#[doc(hidden)]
pub mod __private {
  pub use dash_types;
}
#[cfg(feature = "serde")]
pub mod serialize;

dash_num::make_hash256! {
  /// Hash of a block header.
  BlockHash
}

dash_num::make_hash256! {
  /// SHA256d hash of a serialized transaction.
  TxHash
}

dash_num::make_hash256! {
  /// Merkle tree root hash.
  MerkleRoot
}

pub use block::{Block, BlockInvalid, MAX_DIP0001_BLOCK_SIZE, MAX_LEGACY_BLOCK_SIZE};
pub use block_header::BlockHeader;
pub use codec::MAX_SPTX_PAYLOAD_SIZE;
pub use dash_types::AddrV1;
pub use gov::{
  GovData, GovObject, GovObjectType, GovVote, Proposal, ProposalInvalid, Trigger, VoteOutcome, VoteSignal,
};
pub use hash::{double_sha256, tx_hash};
pub use outpoint::OutPoint;
pub use payload::{
  AssetLock, AssetLockInvalid, AssetUnlock, AssetUnlockInvalid, CbTxInvalid, CoinbaseCommitment, Commitment,
  CommitmentInvalid, FinalCommitment, InputsHash, MnHardFork, MnHardForkInvalid, MnType, NetInfo, PayloadError,
  PayloadInvalid, PlatformNodeId, ProRegTx, ProTxInvalid, ProUpRegTx, ProUpRevTx, ProUpServTx, QuorumHash,
  QuorumVvecHash, SpecialPayload, TxType, VERSIONBITS_NUM_BITS,
};
pub use script::Script;
pub use support::{
  CService, DynBitset, DynBitsetIterator, ExtendedNetInfo, LlmqType, NetInfoEntry, NetInfoPurpose, NetworkType,
  RevocationReason,
};
pub use transaction::{Transaction, TxInvalid, MAX_COINBASE_SCRIPT_SIZE, MAX_TX_EXTRA_PAYLOAD};
pub use tx_in::TxIn;
pub use tx_out::TxOut;
