//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unified BLS cryptography module.

mod error;
mod schemes;

pub use error::BlsError;
pub use schemes::{BlsScChia, BlsScIetf, BlsSchemeId};

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    #[expect(unsafe_code, reason = "blst C FFI")]
    pub(crate) mod blst_ffi;
    pub(crate) mod chia_h2c;
    pub(crate) mod scheme_ops;
    mod scheme_chia;
    mod scheme_ietf;

    #[cfg(feature = "tests")]
    #[doc(hidden)]
    #[expect(clippy::unwrap_used, reason = "test support code")]
    pub mod tests;
  }
}
