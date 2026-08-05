//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

pub mod threshold;

pub use crate::bls::BlsError;
/// BLS signature scheme (determines the DST).
pub use crate::bls::BlsSigId as Scheme;

/// An IETF BLS public key (48-byte compressed G1 point).
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScIetf>;

/// An IETF BLS secret key (32-byte scalar).
pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScIetf>;

/// An IETF BLS signature (96-byte compressed G2 point).
pub type Signature = crate::bls::BlsSignature<crate::bls::BlsScIetf>;
