//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#![cfg_attr(
  any(feature = "bls", feature = "k256"),
  expect(clippy::unwrap_used, reason = "benchmarks rely on trusted test vectors")
)]

#[cfg(feature = "bls")]
mod bls_chia;
#[cfg(feature = "bls")]
mod bls_ietf;
#[path = "../tests/common/mod.rs"]
mod common;
#[cfg(feature = "k256")]
mod k256;

fn main() {
  divan::main();
}
