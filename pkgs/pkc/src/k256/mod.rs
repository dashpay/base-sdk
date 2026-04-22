//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ECDSA signatures using the secp256k1 curve.

mod error;
mod pk;
mod sig;
mod sk;

pub use error::Error;
pub use pk::PublicKey;
pub use sig::{DerSignature, RecoveryId, Signature};
pub use sk::SecretKey;
