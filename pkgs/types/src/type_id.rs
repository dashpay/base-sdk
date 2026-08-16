//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Stable type identifiers.

// nosemgrep: use-pub-roots-only
pub use dash_types_marker::{TypeId, Unencodable};

/// Stable identifier derived from the type name.
pub trait TypeId {
  const TYPE_ID: u32;
}
