//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Diffie-Hellman exchange tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]

use common::*;
use dash_pkc::bls::tests as common;
use dash_pkc::bls_chia::{PublicKey, SecretKey};
use rstest::*;

/// DH exchange produces a shared secret.
#[rstest]
fn dh_exchange_roundtrip(chia_sk0: SecretKey, chia_sk1: SecretKey) {
  let pk0 = chia_sk0.public_key();
  let pk1 = chia_sk1.public_key();
  // sk0 * pk1 == sk1 * pk0
  let shared_a = PublicKey::dh_exchange(&chia_sk0, &pk1).unwrap();
  let shared_b = PublicKey::dh_exchange(&chia_sk1, &pk0).unwrap();
  assert_eq!(shared_a.to_bytes(), shared_b.to_bytes());
}

mod kat {
  use dash_dev::{vec_from_hex, Corpus};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct DhVector {
    sk: String,
    peer_pk: String,
    shared: String,
  }

  #[test]
  fn kat_dh() {
    let vecs: Vec<DhVector> = Corpus::open(env!("CARGO_MANIFEST_DIR"), "bls_chia_dh").vectors("dh_exchange");

    for v in &vecs {
      let sk_bytes: [u8; 32] = vec_from_hex(&v.sk).try_into().unwrap();
      let pk_bytes: [u8; 48] = vec_from_hex(&v.peer_pk).try_into().unwrap();
      let sk = dash_pkc::bls_chia::SecretKey::from_bytes(&sk_bytes).unwrap();
      let peer_pk = dash_pkc::bls_chia::PublicKey::from_bytes(&pk_bytes).unwrap();
      let shared = dash_pkc::bls_chia::PublicKey::dh_exchange(&sk, &peer_pk).unwrap();
      assert_eq!(shared.to_bytes().to_lower_hex_string(), v.shared);
    }
  }
}
