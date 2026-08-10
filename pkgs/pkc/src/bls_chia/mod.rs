//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signatures (non-standard hash-to-G2, min-pubkey-size).

pub mod threshold;

pub use crate::bls::BlsError;

/// A legacy BLS public key (48-byte G1 point in legacy serialization).
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScChia>;

/// A legacy BLS secret key (32-byte scalar).
pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScChia>;

/// A legacy BLS signature (96-byte G2 point in legacy serialization).
pub type Signature = crate::bls::BlsSignature<crate::bls::BlsScChia>;
