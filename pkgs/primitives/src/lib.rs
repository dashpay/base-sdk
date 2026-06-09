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

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
#[doc(hidden)]
pub mod __private {
  pub use dash_types;
}

pub mod block;
pub mod block_header;
pub mod codec;
pub mod gov;
pub mod hash;
pub mod outpoint;
pub mod payload;
pub mod script;
#[cfg(feature = "serde")]
pub mod serialize;
pub mod support;
pub mod transaction;
pub mod tx_in;
pub mod tx_out;
pub mod tx_types;
pub mod validation;

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

pub use block::Block;
pub use block_header::BlockHeader;
pub use codec::MAX_SPTX_PAYLOAD_SIZE;
pub use dash_types::AddrV1;
pub use outpoint::OutPoint;
pub use script::Script;
pub use support::{
  CService, DynBitset, ExtendedNetInfo, LlmqType, NetInfoEntry, NetInfoPurpose, NetworkType, RevocationReason,
};
pub use transaction::Transaction;
pub use tx_in::TxIn;
pub use tx_out::TxOut;
pub use tx_types::{MnType, TxType};
