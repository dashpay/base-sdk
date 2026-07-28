//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory messages: inv, getdata, notfound.

use crate::codec::codec_p2p;
use crate::prelude::*;
use crate::primitives::Inventory;

use dash_types::TypeId;

/// Announces available inventory to a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inv {
  /// Inventory items being announced.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(Inv { inventory });

/// Requests specific inventory items from a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetData {
  /// Inventory items being requested.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(GetData { inventory });

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
