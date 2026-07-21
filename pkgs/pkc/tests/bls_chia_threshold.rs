//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold split and recovery tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use crate::common::bls::*;

use dash_num::Hash256;
use dash_pkc::bls_chia::{threshold, BlsError, SecretKey};
use rstest::*;

/// Threshold split/recover with legacy signing.
#[rstest]
fn threshold_split_recover(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let ids = common::sequential_ids(5);
  let mut rng = rand_core::OsRng;
  let shares = threshold::split_sk(&chia_sk0, 3, &ids, &mut rng).unwrap();
  let full_sig = chia_sk0.sign(&msg32);

  let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(&msg32)).collect();
  let subset: Vec<&threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
  let recovered = threshold::recover_sig(&subset).unwrap();
  assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
}

/// An id that reduces to zero mod r (the null id, or the group order
/// itself) would make its share equal the master key; reject it.
#[rstest]
#[case::null_id([0u8; 32])]
#[case::group_order(GROUP_ORDER)]
fn split_rejects_zero_reducing_ids(chia_sk0: SecretKey, #[case] zero_id: [u8; 32]) {
  let mut ids = common::sequential_ids(3);
  let mut rng = rand_core::OsRng;

  ids[1] = Hash256::from(zero_id);
  assert_eq!(
    threshold::split_sk(&chia_sk0, 2, &ids, &mut rng).unwrap_err(),
    BlsError::InvalidShareId
  );
}

/// 1 and r+1 are distinct hashes but the same scalar mod r; a raw-byte
/// duplicate check misses them and interpolation would divide by zero.
#[rstest]
fn split_rejects_ids_congruent_mod_order(chia_sk0: SecretKey) {
  let mut one = [0u8; 32];
  one[31] = 1;
  let mut order_plus_one = GROUP_ORDER;
  order_plus_one[31] = 2;
  let ids = [Hash256::from(one), Hash256::from(order_plus_one)];

  let mut rng = rand_core::OsRng;
  assert_eq!(
    threshold::split_sk(&chia_sk0, 2, &ids, &mut rng).unwrap_err(),
    BlsError::DuplicateShareId
  );
}

/// A verification vector shorter than 2 elements is malformed
/// (polynomial evaluation requires at least 2 coefficients).
#[rstest]
fn derive_pk_share_rejects_short_verification_vector(chia_sk0: SecretKey) {
  let pk = chia_sk0.public_key();
  let id = common::make_id(1);
  assert_eq!(
    threshold::derive_pk_share(&[&pk], &id).unwrap_err(),
    BlsError::InvalidVerificationVector
  );
}

/// Recovery below threshold succeeds but yields a point unrelated to the
/// master signature; callers must verify recovered signatures.
#[rstest]
fn sub_threshold_recovery_does_not_verify(chia_sk0: SecretKey, msg32: [u8; 32]) {
  let ids = common::sequential_ids(5);
  let mut rng = rand_core::OsRng;
  let shares = threshold::split_sk(&chia_sk0, 3, &ids, &mut rng).unwrap();
  let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(&msg32)).collect();
  let pk = chia_sk0.public_key();

  let below: Vec<&threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[1]];
  let recovered = threshold::recover_sig(&below).unwrap();
  assert!(recovered.verify(&msg32, &pk).is_err());

  let at: Vec<&threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
  let recovered = threshold::recover_sig(&at).unwrap();
  assert!(recovered.verify(&msg32, &pk).is_ok());
}
