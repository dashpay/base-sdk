//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of possession tests for bls_ietf.

mod common;

use crate::common::bls::*;

use dash_pkc::bls_ietf::SecretKey;
use rstest::*;

/// Proof of possession round-trips.
#[rstest]
fn pop_prove_verify(ietf_sk0: SecretKey) {
  let pop = ietf_sk0.prove_possession();
  let pk = ietf_sk0.public_key();
  assert!(pk.verify_possession(&pop).is_ok());
}

/// PoP from a different key is rejected.
#[rstest]
fn pop_rejects_wrong_key(ietf_sk0: SecretKey, ietf_sk1: SecretKey) {
  let pop = ietf_sk0.prove_possession();
  let wrong_pk = ietf_sk1.public_key();
  assert!(wrong_pk.verify_possession(&pop).is_err());
}
