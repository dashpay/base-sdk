//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and batch verification for IETF BLS.

use super::pk::PublicKey;
use super::sig::Signature;
use super::sk::SecretKey;
use super::DST;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::{BlsError, BlsScIetf};
use crate::prelude::*;

use blst::min_pk;
use blst::BLST_ERROR;

/// Aggregate multiple public keys into one.
pub fn aggregate_pk(keys: &[&PublicKey]) -> Result<PublicKey, BlsError> {
  let inner: Vec<_> = keys.iter().map(|key| &key.0).collect();
  BlsScIetf::aggregate_pk(&inner).map(PublicKey::from_inner)
}

/// Aggregate multiple signatures into one.
pub fn aggregate_sig(sigs: &[&Signature]) -> Result<Signature, BlsError> {
  let inner: Vec<_> = sigs.iter().map(|sig| &sig.0).collect();
  BlsScIetf::aggregate_sig(&inner).map(Signature::from_inner)
}

/// Verify an aggregated signature where every signer signed the same message.
pub fn fast_verify_aggregates(sig: &Signature, msg: &[u8], pks: &[&PublicKey]) -> Result<(), BlsError> {
  let inner: Vec<_> = pks.iter().map(|pk| &pk.0).collect();
  BlsScIetf::fast_verify_aggregates(&sig.0, msg, &inner)
}

/// Verify an aggregated signature where each signer signed a distinct message.
pub fn verify_aggregates(sig: &Signature, msgs: &[&[u8]], pks: &[&PublicKey]) -> Result<(), BlsError> {
  if pks.len() != msgs.len() {
    return Err(BlsError::CountMismatch);
  }
  if pks.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  let inner_pks: Vec<&min_pk::PublicKey> = pks.iter().map(|k| &k.0).collect();
  let result = sig.0.aggregate_verify(true, msgs, DST, &inner_pks, true);
  if result == BLST_ERROR::BLST_SUCCESS {
    Ok(())
  } else {
    Err(BlsError::VerifyFailed)
  }
}

/// Securely aggregate and verify signatures with public-key weighting.
///
/// Algorithm:
/// 1. Sort public keys by serialized (compressed) bytes
/// 2. Compute `pk_hash = SHA256(pk1 || pk2 || ... || pkN)` (sorted order)
/// 3. For each sorted pk at index i: `weight_i = SHA256(i_as_4_bytes ||
///    pk_hash) mod order`
/// 4. Compute weighted public key: `agg_pk = sum(weight_i * pk_i)`
/// 5. Verify the aggregate signature against `agg_pk` and the message
pub fn secure_verify_aggregates(sig: &Signature, msg: &[u8], pks: &[&PublicKey]) -> Result<(), BlsError> {
  let inner: Vec<_> = pks.iter().map(|pk| &pk.0).collect();
  BlsScIetf::secure_verify_aggregates(&sig.0, msg, &inner)
}

/// Sum multiple secret keys (mod group order).
pub fn aggregate_sk(keys: &[&SecretKey]) -> Result<SecretKey, BlsError> {
  let inner: Vec<_> = keys.iter().map(|key| &key.0).collect();
  BlsScIetf::aggregate_sk(&inner).map(SecretKey)
}
