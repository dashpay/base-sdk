//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared internals used by multiple BLS modules.

#[cfg(any(feature = "bls_ietf", feature = "bls_chia"))]
pub(crate) mod bls;
