//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signatures (non-standard hash-to-G2, min-pubkey-size).

mod agg;
mod sig;

pub mod threshold;

pub use crate::bls::BlsError;

pub use agg::{aggregate_sig, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates};
pub use sig::Signature;

/// A legacy BLS public key (48-byte G1 point in legacy serialization).
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScChia>;

/// A legacy BLS secret key (32-byte scalar).
pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScChia>;

// Compile-time contract: must match bls_ietf's shared API surface.
const _: () = {
  use crate::common::bls::contract::*;
  impl BlsSignature for Signature {
    type Error = BlsError;
    type PublicKey = PublicKey;
    type Msg = [u8; 32];
    fn from_bytes(b: &[u8; 96]) -> Result<Self, BlsError> {
      Signature::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 96] {
      self.to_bytes()
    }
    fn verify(&self, msg: &[u8; 32], pk: &PublicKey) -> Result<(), BlsError> {
      self.verify(msg, pk)
    }
  }
};
