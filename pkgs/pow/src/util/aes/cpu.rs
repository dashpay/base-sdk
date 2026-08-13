//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Best available AES round at runtime.
//!
//! Hardware-accelerated on aarch64 with `aes_hw`, scalar T-table fallback
//! otherwise.

#[cfg(all(feature = "aes_hw", target_arch = "aarch64", test))]
pub(crate) use super::aarch64::round;
#[cfg(all(feature = "aes_hw", target_arch = "aarch64"))]
pub(crate) use super::aarch64::round_nk;
#[cfg(not(all(feature = "aes_hw", target_arch = "aarch64")))]
pub(crate) use super::scalar::{round, round_nk};
