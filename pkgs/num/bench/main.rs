//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks.

use dash_num::Arith256;

#[divan::bench]
fn arith256_mul(bencher: divan::Bencher) {
  let a = Arith256::from_u64(0xdead_beef_cafe_babe);
  let b = Arith256::from_u64(0x1234_5678_9abc_def0);
  bencher.bench(|| a * b);
}

#[divan::bench]
fn arith256_div(bencher: divan::Bencher) {
  let a = Arith256::MAX;
  let b = Arith256::from_u64(0xdead_beef);
  bencher.bench(|| a / b);
}

fn main() {
  divan::main();
}
