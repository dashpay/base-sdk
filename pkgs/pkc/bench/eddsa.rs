//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for the `eddsa` (ed25519) feature

use dash_pkc::eddsa::tests::ALICE_PK;
use dash_pkc::eddsa::{EddsaPkBytes, EddsaPublicKey};
use dash_types::Hashable;

#[divan::bench]
fn deser_pk(bencher: divan::Bencher) {
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| EddsaPublicKey::from_bytes(&ALICE_PK).unwrap());
}

#[divan::bench]
fn hash_pk(bencher: divan::Bencher) {
  let bag = EddsaPkBytes::from(ALICE_PK);
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| Hashable::hash(&bag));
}
