//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#![cfg_attr(
  any(feature = "bls", feature = "ecdsa", feature = "eddsa"),
  expect(clippy::unwrap_used, reason = "benchmarks rely on trusted test vectors")
)]

extern crate alloc;

#[cfg(feature = "bls")]
mod bls;
#[cfg(any(feature = "bls", feature = "ecdsa", feature = "eddsa"))]
#[path = "../src/tests.rs"]
mod common;
#[cfg(feature = "ecdsa")]
mod ecdsa;
#[cfg(feature = "eddsa")]
mod eddsa;

fn main() {
  divan::main();
}
