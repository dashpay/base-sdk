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

mod prelude;

use types::byte::define_byte_type;
use types::hash256::define_hash256_type;

pub mod block;
pub mod block_header;
pub mod codec;
pub mod error;
pub mod gov;
pub mod hash;
pub mod outpoint;
pub mod payload;
pub mod script;
pub mod support;
pub mod transaction;
pub mod tx_in;
pub mod tx_out;
pub mod tx_types;
pub mod types;
pub mod validation;
pub mod wire;

define_hash256_type! {
  /// Hash of a block header.
  BlockHash
}

define_hash256_type! {
  /// SHA256d hash of a serialized transaction.
  TxHash
}

define_hash256_type! {
  /// Merkle tree root hash.
  MerkleRoot
}

define_hash256_type! {
  /// Hash of serialized transaction inputs.
  InputsHash
}

define_hash256_type! {
  /// LLMQ quorum identifier.
  QuorumHash
}

define_hash256_type! {
  /// Quorum verification vector hash.
  QuorumVvecHash
}

define_byte_type! {
  /// Platform node identifier for Evo masternodes.
  PlatformNodeId, 20
}

define_byte_type! {
  /// Raw BLS public key bytes (48 bytes, unvalidated).
  BlsPublicKeyBytes, 48
}

define_byte_type! {
  /// Raw BLS signature bytes (96 bytes, unvalidated).
  BlsSignatureBytes, 96
}

/// Re-export from `dash-script`.
pub use dash_script::KeyId;

pub use block::Block;
pub use block_header::BlockHeader;
pub use outpoint::OutPoint;
pub use script::Script;
pub use support::{
  CService, DynBitset, ExtendedNetInfo, LlmqType, NetInfoEntry, NetInfoPurpose, NetworkType, RevocationReason,
};
pub use transaction::{Transaction, MAX_EXTRA_PAYLOAD_SIZE};
pub use tx_in::TxIn;
pub use tx_out::TxOut;
pub use tx_types::{MnType, TxType};
pub use validation::DeploymentContext;
