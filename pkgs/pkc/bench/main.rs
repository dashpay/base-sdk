//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#![cfg_attr(
  any(feature = "bls", feature = "ecdsa", feature = "eddsa"),
  expect(clippy::unwrap_used, reason = "benchmarks rely on trusted test vectors")
)]

#[cfg(feature = "bls")]
mod bls;
#[cfg(feature = "ecdsa")]
mod ecdsa;
#[cfg(feature = "eddsa")]
mod eddsa;

fn main() {
  divan::main();
}
