//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

mod agg;
mod sig;

pub mod threshold;

pub use crate::bls::BlsError;
/// BLS signature scheme (determines the DST).
pub use crate::bls::BlsSigId as Scheme;

pub use agg::{aggregate_sig, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates};
pub use sig::Signature;

/// An IETF BLS public key (48-byte compressed G1 point).
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScIetf>;

/// An IETF BLS secret key (32-byte scalar).
pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScIetf>;

// Compile-time contract: if any of these methods are
// removed or their signatures change, this block fails.
const _: () = {
  use crate::common::bls::contract::*;
  impl BlsSignature for Signature {
    type Error = BlsError;
    type PublicKey = PublicKey;
    type Msg = [u8];
    fn from_bytes(b: &[u8; 96]) -> Result<Self, BlsError> {
      Signature::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 96] {
      self.to_bytes()
    }
    fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<(), BlsError> {
      self.verify(msg, pk)
    }
  }
};
