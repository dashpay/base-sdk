//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signatures (non-standard hash-to-G2, min-pubkey-size).

mod agg;
mod sig;
mod sk;

pub mod threshold;

pub use crate::bls::BlsError;

pub use agg::{aggregate_sig, aggregate_sk, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates};
pub use sig::Signature;
pub use sk::SecretKey;

/// A legacy BLS public key (48-byte G1 point in legacy serialization).
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScChia>;

// Compile-time contract: must match bls_ietf's shared API surface.
const _: () = {
  use crate::common::bls::contract::*;
  impl BlsSecretKey for SecretKey {
    type Error = BlsError;
    type PublicKey = PublicKey;
    type Signature = Signature;
    type Msg = [u8; 32];
    fn generate(ikm: &[u8]) -> Result<Self, BlsError> {
      SecretKey::generate(ikm)
    }
    fn from_bytes(b: &[u8; 32]) -> Result<Self, BlsError> {
      SecretKey::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 32] {
      self.to_bytes()
    }
    fn public_key(&self) -> PublicKey {
      self.public_key()
    }
    fn sign(&self, msg: &[u8; 32]) -> Signature {
      self.sign(msg)
    }
    fn dh_exchange(&self, peer_pk: &PublicKey) -> Result<PublicKey, BlsError> {
      self.dh_exchange(peer_pk)
    }
  }
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
