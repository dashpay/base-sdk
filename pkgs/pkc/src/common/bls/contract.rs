//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compile-time contract enforcing that both BLS modules expose the same core
//! API surface.
//!
//! This module is never used at runtime, it exists solely so that adding a
//! method to one module without the other triggers a build failure.
//!
//! Threshold operations (`split_sk`, `recover_sig`, `derive_pk_share`) use
//! `Hash256` participant IDs (big-endian, reduced mod the scalar field
//! order).

/// Marker trait asserting the minimum BLS secret key API.
pub(crate) trait BlsSecretKey: Clone + Sized {
  type Error;
  type PublicKey;
  type Signature;
  type Msg: ?Sized;

  fn generate(ikm: &[u8]) -> Result<Self, Self::Error>;
  fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Self::Error>;
  fn to_bytes(&self) -> [u8; 32];
  fn public_key(&self) -> Self::PublicKey;
  fn sign(&self, msg: &Self::Msg) -> Self::Signature;
}

/// Marker trait asserting the minimum BLS public key API.
pub(crate) trait BlsPublicKey: Clone + Sized {
  type Error;
  type SecretKey;

  fn from_bytes(bytes: &[u8; 48]) -> Result<Self, Self::Error>;
  fn to_bytes(&self) -> [u8; 48];
  fn dh_exchange(sk: &Self::SecretKey, peer_pk: &Self) -> Result<Self, Self::Error>;
}

/// Marker trait asserting the minimum BLS signature API.
pub(crate) trait BlsSignature: Clone + Sized {
  type Error;
  type PublicKey;
  type Msg: ?Sized;

  fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Self::Error>;
  fn to_bytes(&self) -> [u8; 96];
  fn verify(&self, msg: &Self::Msg, pk: &Self::PublicKey) -> Result<(), Self::Error>;
}
