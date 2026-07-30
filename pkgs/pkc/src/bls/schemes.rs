//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS scheme marker types.

use dash_types::Unencodable;

/// Legacy (Chia) BLS scheme marker.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub(crate) enum BlsScChia {}

/// IETF-standard BLS scheme marker.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub(crate) enum BlsScIetf {}
