//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unified BLS cryptography module.

mod error;
mod public_bytes;
mod schemes;
mod secret_bytes;
mod sig_bytes;
mod sig_id;

pub use error::BlsError;
pub use public_bytes::{BlsPkBytes, BLS_PK_LEN};
pub use schemes::{BlsScChia, BlsScIetf, BlsSchemeId};
pub use secret_bytes::{BlsSkBytes, BLS_SK_LEN};
pub use sig_bytes::{BlsSigBytes, BLS_SIG_LEN};
pub use sig_id::BlsSigId;

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    mod public_ops;
    mod scheme_chia;
    mod scheme_ietf;
    mod secret_ops;
    mod share_ops;
    mod sig_aggregate;
    mod sig_basic;
    mod sig_pop;
    mod sig_threshold;
    #[expect(unsafe_code, reason = "blst C FFI")]
    pub(crate) mod blst_ffi;
    pub(crate) mod chia_h2c;
    pub(crate) mod scheme_ops;

    #[cfg(feature = "tests")]
    #[doc(hidden)]
    #[expect(clippy::unwrap_used, reason = "test support code")]
    pub mod tests;

    pub use public_ops::BlsPublicKey;
    pub use scheme_ops::BlsScheme;
    pub use secret_ops::BlsSecretKey;
    pub use share_ops::{BlsSigShare, BlsSkShare};
    pub use sig_basic::BlsSignature;
  }
}
