//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory messages and types.

use crate::codec::codec_p2p;
use crate::prelude::*;

use dash_num::Hash256;
use dash_primitives::hash_impl;
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_num};

use core::fmt;

/// Requests specific inventory items from a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetData {
  /// Inventory items being requested.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(GetData { inventory });

enum_map! {
  /// Inventory object type.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum InvType, u32, Unknown {
    /// Error / not used.
    Error = 0 => "error",
    /// Transaction.
    Tx = 1 => "tx",
    /// Block.
    Block = 2 => "block",
    /// Filtered block (BIP37).
    FilteredBlock = 3 => "filtered_block",
    /// Governance object.
    GovernanceObject = 17 => "governance_object",
    /// Governance object vote.
    GovernanceObjectVote = 18 => "governance_object_vote",
    /// Compact block (BIP152).
    CompactBlock = 20 => "compact_block",
  }
}

impl_num!(InvType, u32);

hash_impl!(InvType);

/// An inventory vector: a typed 32-byte hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inventory {
  /// Object type.
  #[cfg_attr(feature = "serde", serde(rename = "type"))]
  pub inv_type: InvType,
  /// Object hash.
  pub hash: Hash256,
}

codec_p2p!(Inventory { inv_type, hash });

impl fmt::Display for Inventory {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.inv_type, self.hash)
  }
}

/// Announces available inventory to a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inv {
  /// Inventory items being announced.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(Inv { inventory });

/// Indicates requested inventory items were not found.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotFound {
  /// Missing inventory items.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(NotFound { inventory });

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_inv() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "inv");
    let items = corpus.entries::<Inv>("inv", check_wire);
    assert_serde_rt("inv", &items);
  }
}
