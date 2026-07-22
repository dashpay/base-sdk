//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold split and recovery tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

mod common;

use crate::common::bls::*;

use dash_pkc::bls_chia::SecretKey;
use rstest::*;

/// Threshold split/recover with legacy signing.
#[rstest]
fn threshold_split_recover(chia_sk0: SecretKey, msg32: [u8; 32]) {
  use dash_pkc::bls_chia::threshold;

  let ids = common::sequential_ids(5);
  let mut rng = rand_core::OsRng;
  let shares = threshold::split_sk(&chia_sk0, 3, &ids, &mut rng).unwrap();
  let full_sig = chia_sk0.sign(&msg32);

  let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(&msg32)).collect();
  let subset: Vec<&threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
  let recovered = threshold::recover_sig(&subset).unwrap();
  assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
}
