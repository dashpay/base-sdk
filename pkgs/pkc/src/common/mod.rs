//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared internals used by multiple BLS modules.

#[cfg(feature = "bls")]
#[expect(unsafe_code, reason = "blst C FFI")]
pub(crate) mod bls;
