//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and secure verification for legacy BLS.

use super::pk::PublicKey;
use super::sig::Signature;
use super::sk::SecretKey;
use crate::bls::blst_ffi::{self, Point, G1};
use crate::bls::BlsError;
use crate::prelude::*;

use sha2::{Digest, Sha256};

/// Aggregate multiple legacy BLS public keys (simple point addition in G1).
pub fn aggregate_pk(keys: &[&PublicKey]) -> Result<PublicKey, BlsError> {
  if keys.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  let mut acc = keys[0].0.to_projective();
  for k in &keys[1..] {
    acc = acc + k.0.to_projective();
  }
  Ok(PublicKey::from_inner(acc.to_affine()))
}

/// Aggregate multiple legacy BLS signatures (simple point addition in G2).
pub fn aggregate_sig(sigs: &[&Signature]) -> Result<Signature, BlsError> {
  if sigs.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  let mut acc = sigs[0].0.to_projective();
  for s in &sigs[1..] {
    acc = acc + s.0.to_projective();
  }
  Ok(Signature::from_inner(acc.to_affine()))
}

/// Verify an aggregated legacy BLS signature over one message and multiple
/// public keys.
pub fn verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), BlsError> {
  if pks.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  let agg_pk = aggregate_pk(pks)?;
  sig.verify(msg, &agg_pk)
}

/// Verify an aggregated legacy BLS signature where every signer signed the
/// same message. Equivalent to `verify_aggregates` for the legacy scheme.
pub fn fast_verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), BlsError> {
  verify_aggregates(sig, msg, pks)
}

/// Securely aggregate and verify signatures with public-key weighting.
///
/// Algorithm:
/// 1. Sort public keys by serialized (legacy) bytes
/// 2. Compute `pk_hash = SHA256(pk1 || pk2 || ... || pkN)` (sorted order)
/// 3. For each sorted pk at index i: `weight_i = SHA256(i_as_4_bytes ||
///    pk_hash) mod order`
/// 4. Compute weighted public key: `agg_pk = sum(weight_i * pk_i)`
/// 5. Verify the aggregate signature against `agg_pk` and the message
pub fn secure_verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), BlsError> {
  if pks.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }

  let mut sorted: Vec<[u8; 48]> = pks.iter().map(|pk| pk.to_bytes()).collect();
  sorted.sort();

  let mut hasher = Sha256::new();
  for pk_bytes in &sorted {
    hasher.update(pk_bytes);
  }
  let pk_hash: [u8; 32] = hasher.finalize().into();

  let mut acc = G1::identity();

  for (i, pk_bytes) in sorted.iter().enumerate() {
    // weight = SHA256(i_as_4_bytes_be || pk_hash) mod order
    let mut weight_hasher = Sha256::new();
    let idx_bytes = (i as u32).to_be_bytes();
    weight_hasher.update(idx_bytes);
    weight_hasher.update(pk_hash);
    let weight_hash: [u8; 32] = weight_hasher.finalize().into();

    // blst_p1_mult reduces internally.
    let weight = blst_ffi::scalar_from_bendian(&weight_hash);

    let pk = PublicKey::from_bytes(pk_bytes).map_err(|_| BlsError::InvalidPublicKey)?;
    acc = acc + pk.0.to_projective().mul_scalar(&weight.b, 256);
  }

  let agg_pk = PublicKey::from_inner(acc.to_affine());

  sig.verify(msg, &agg_pk)
}

/// Sum multiple secret keys (mod group order).
pub fn aggregate_sk(keys: &[&SecretKey]) -> Result<SecretKey, BlsError> {
  use zeroize::Zeroize;
  if keys.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  let byte_vecs = zeroize::Zeroizing::new(keys.iter().map(|k| k.to_bytes()).collect::<Vec<[u8; 32]>>());
  let mut out_bytes = crate::common::bls::sum_sk_scalars(&byte_vecs).map_err(|()| BlsError::InvalidSecretKey)?;
  let result = SecretKey::from_bytes(&out_bytes).map_err(|_| BlsError::InvalidSecretKey);
  out_bytes.zeroize();
  result
}
