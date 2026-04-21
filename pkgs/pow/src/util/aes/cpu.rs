//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Best available AES round at runtime.
//!
//! Hardware-accelerated on aarch64 with `aes_hw`, scalar T-table fallback
//! otherwise.

cfg_if::cfg_if! {
  if #[cfg(all(feature = "aes_hw", target_arch = "aarch64"))] {
    #[cfg(test)]
    pub(crate) use super::aarch64::round;
    pub(crate) use super::aarch64::round_nk;
  } else {
    pub(crate) use super::scalar::{round, round_nk};
  }
}
