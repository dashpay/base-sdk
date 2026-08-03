//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unified BLS cryptography module.

mod error;
mod schemes;
mod sig_id;

pub use error::BlsError;
pub use schemes::{BlsScChia, BlsScIetf, BlsSchemeId};
pub use sig_id::BlsSigId;

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    mod scheme_chia;
    mod scheme_ietf;
    #[expect(unsafe_code, reason = "blst C FFI")]
    pub(crate) mod blst_ffi;
    pub(crate) mod chia_h2c;
    pub(crate) mod scheme_ops;

    #[cfg(feature = "tests")]
    #[doc(hidden)]
    #[expect(clippy::unwrap_used, reason = "test support code")]
    pub mod tests;
  }
}
