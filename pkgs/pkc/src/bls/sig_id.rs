//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signature types.

#[cfg(feature = "codec")]
use dash_types::type_id::Unencodable;

/// BLS signature variant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "codec", derive(Unencodable))]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum BlsSigId {
  /// Basic scheme (NUL augmentation).
  Basic,
  /// Proof of Possession scheme.
  ProofOfPossession,
}
