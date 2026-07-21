//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold split and recovery tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use crate::common::bls::*;

use dash_num::Hash256;
use dash_pkc::bls_ietf::{threshold, BlsError, SecretKey};
use rstest::*;

/// Split into 5 shares, recover from 3, verify the recovered
/// signature matches the original.
#[rstest]
fn threshold_split_recover(ietf_sk0: SecretKey) {
  let ids = common::sequential_ids(5);
  let mut rng = rand_core::OsRng;
  let shares = threshold::split_sk(&ietf_sk0, 3, &ids, &mut rng).unwrap();
  assert_eq!(shares.len(), 5);

  let msg = b"threshold test message";
  let full_sig = ietf_sk0.sign(msg);

  let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(msg)).collect();

  // Recover from shares 0, 2, 4 (any 3 of 5).
  let subset: Vec<&threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
  let recovered = threshold::recover_sig(&subset).unwrap();
  assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
}

/// Threshold recovery with insufficient shares fails.
#[rstest]
fn threshold_insufficient_shares() {
  assert!(threshold::recover_sig(&[]).is_err());
}

/// Invalid threshold parameters are rejected.
#[rstest]
fn threshold_invalid_params(ietf_sk0: SecretKey) {
  let mut rng = rand_core::OsRng;
  let ids = common::sequential_ids(5);
  assert!(threshold::split_sk(&ietf_sk0, 0, &ids, &mut rng).is_err());
  let ids6 = common::sequential_ids(5);
  assert!(threshold::split_sk(&ietf_sk0, 6, &ids6, &mut rng).is_err());
}

/// An id reducing to zero mod r would leak the master key via its share.
#[rstest]
#[case::null_id([0u8; 32])]
#[case::group_order(GROUP_ORDER)]
fn split_rejects_zero_reducing_ids(ietf_sk0: SecretKey, #[case] zero_id: [u8; 32]) {
  let mut ids = common::sequential_ids(3);
  let mut rng = rand_core::OsRng;

  ids[1] = Hash256::from(zero_id);
  assert_eq!(
    threshold::split_sk(&ietf_sk0, 2, &ids, &mut rng).unwrap_err(),
    BlsError::InvalidShareId
  );
}

/// 1 and r+1 collide as scalars mod r; a raw-byte check misses them.
#[rstest]
fn split_rejects_ids_congruent_mod_order(ietf_sk0: SecretKey) {
  let mut one = [0u8; 32];
  one[31] = 1;
  let mut order_plus_one = GROUP_ORDER;
  order_plus_one[31] = 2;
  let ids = [Hash256::from(one), Hash256::from(order_plus_one)];

  let mut rng = rand_core::OsRng;
  assert_eq!(
    threshold::split_sk(&ietf_sk0, 2, &ids, &mut rng).unwrap_err(),
    BlsError::DuplicateShareId
  );
}

/// A verification vector shorter than 2 elements is malformed.
#[rstest]
fn derive_pk_share_rejects_short_verification_vector(ietf_sk0: SecretKey) {
  let pk = ietf_sk0.public_key();
  let id = common::make_id(1);
  assert_eq!(
    threshold::derive_pk_share(&[&pk], &id).unwrap_err(),
    BlsError::InvalidVerificationVector
  );
}
