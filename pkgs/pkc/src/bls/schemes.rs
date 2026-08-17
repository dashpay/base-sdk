//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS scheme trait and marker types.

use dash_types::type_id::{TypeId, Unencodable};

/// BLS scheme discriminator.
pub trait BlsSchemeId: TypeId + 'static {}

/// Legacy (Chia) BLS scheme marker.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId, Unencodable)]
pub enum BlsScChia {}

impl BlsSchemeId for BlsScChia {}

/// IETF-standard BLS scheme marker.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId, Unencodable)]
pub enum BlsScIetf {}

impl BlsSchemeId for BlsScIetf {}
