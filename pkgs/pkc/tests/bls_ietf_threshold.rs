//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold split and recovery tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use dash_pkc::bls_ietf::SecretKey;
use rstest::*;

/// Key derived from all-zero IKM.
#[fixture]
fn sk_seed0() -> SecretKey {
  SecretKey::generate(&common::SEED_0).unwrap()
}

/// Split into 5 shares, recover from 3, verify the recovered
/// signature matches the original.
#[rstest]
fn threshold_split_recover(sk_seed0: SecretKey) {
  use dash_pkc::bls_ietf::threshold;

  let ids = common::sequential_ids(5);
  let mut rng = rand_core::OsRng;
  let shares = threshold::split_sk(&sk_seed0, 3, &ids, &mut rng).unwrap();
  assert_eq!(shares.len(), 5);

  let msg = b"threshold test message";
  let full_sig = sk_seed0.sign(msg);

  let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(msg)).collect();

  // Recover from shares 0, 2, 4 (any 3 of 5).
  let subset: Vec<&threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
  let recovered = threshold::recover_sig(&subset).unwrap();
  assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
}

/// Threshold recovery with insufficient shares fails.
#[rstest]
fn threshold_insufficient_shares() {
  use dash_pkc::bls_ietf::threshold;
  assert!(threshold::recover_sig(&[]).is_err());
}

/// Invalid threshold parameters are rejected.
#[rstest]
fn threshold_invalid_params(sk_seed0: SecretKey) {
  use dash_pkc::bls_ietf::threshold;
  let mut rng = rand_core::OsRng;
  let ids = common::sequential_ids(5);
  assert!(threshold::split_sk(&sk_seed0, 0, &ids, &mut rng).is_err());
  let ids6 = common::sequential_ids(5);
  assert!(threshold::split_sk(&sk_seed0, 6, &ids6, &mut rng).is_err());
}
