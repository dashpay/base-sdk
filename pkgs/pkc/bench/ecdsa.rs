//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for the ecdsa (secp256k1) feature

use dash_pkc::ecdsa::tests::{message_hash, ALICE_SK};
use dash_pkc::ecdsa::{EcdsaPublicKey, EcdsaSecretKey};

fn test_key() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&ALICE_SK).unwrap()
}

#[divan::bench]
fn sign(bencher: divan::Bencher) {
  let sk = test_key();
  bencher.counter(divan::counter::ItemsCount::new(1u32)).bench(|| {
    let msg = message_hash(42);
    sk.sign(&msg).unwrap()
  });
}

#[divan::bench]
fn verify(bencher: divan::Bencher) {
  let sk = test_key();
  let msg = message_hash(99);
  let sig = sk.sign(&msg).unwrap();
  let pk = sk.public_key();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| pk.verify(&msg, &sig));
}

#[divan::bench]
fn sign_recoverable(bencher: divan::Bencher) {
  let sk = test_key();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| sk.sign_recoverable(&message_hash(7)).unwrap());
}

#[divan::bench]
fn recover(bencher: divan::Bencher) {
  let sk = test_key();
  let msg = message_hash(55);
  let (sig, rid) = sk.sign_recoverable(&msg).unwrap();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| EcdsaPublicKey::recover(&msg, &sig, rid));
}

#[divan::bench]
fn ser_pk(bencher: divan::Bencher) {
  let pk = test_key().public_key();
  bencher.bench(|| pk.to_bytes());
}

#[divan::bench]
fn deser_pk(bencher: divan::Bencher) {
  let bytes = test_key().public_key().to_bytes();
  bencher.bench(|| EcdsaPublicKey::from_bytes(&bytes));
}

#[cfg(feature = "std")]
mod worker_benches {
  use dash_pkc::ecdsa::tests::{message_hash, BOB_SK};
  use dash_pkc::ecdsa::{EcdsaPublicKey, EcdsaSecretKey, EcdsaSignature};
  use dash_pkc::worker;

  fn setup_sigs(n: usize) -> Vec<(EcdsaSignature, EcdsaPublicKey, [u8; 32])> {
    let sk = EcdsaSecretKey::from_bytes(&BOB_SK).unwrap();
    let pk = sk.public_key();
    (0..n)
      .map(|i| {
        let msg = message_hash(i as u16);
        let sig = sk.sign(&msg).unwrap();
        (sig, pk.clone(), msg)
      })
      .collect()
  }

  #[divan::bench(args = [100, 1000])]
  fn worker_verify_n(bencher: divan::Bencher, n: usize) {
    let tuples = setup_sigs(n);
    bencher
      .counter(divan::counter::ItemsCount::new(n))
      .bench(|| worker::par_verify(&tuples, |(sig, pk, msg)| pk.verify(msg, sig).is_ok()));
  }
}
