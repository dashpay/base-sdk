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
mod tx_types;
mod validation;

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

dash_num::make_hash256! {
  /// Hash of serialized transaction inputs.
  InputsHash
}

dash_num::make_hash256! {
  /// LLMQ quorum identifier.
  QuorumHash
}

dash_num::make_hash256! {
  /// Quorum verification vector hash.
  QuorumVvecHash
}

pub use block::{Block, BlockInvalid};
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
  CommitmentInvalid, FinalCommitment, MnHardFork, MnHardForkInvalid, NetInfo, PayloadError, PayloadInvalid, ProRegTx,
  ProUpRegTx, ProUpRevTx, ProUpServTx, SpecialPayload,
};
pub use script::Script;
pub use support::{
  CService, DynBitset, DynBitsetIterator, ExtendedNetInfo, LlmqType, NetInfoEntry, NetInfoPurpose, NetworkType,
  RevocationReason,
};
pub use transaction::{Transaction, TxInvalid};
pub use tx_in::TxIn;
pub use tx_out::TxOut;
pub use tx_types::{MnType, TxType};
pub use validation::ProTxInvalid;
