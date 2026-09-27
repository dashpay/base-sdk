//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of work chained hash tests.

use dash_pow::hash;
use hex_conservative::hex;
use rstest::rstest;

#[rstest]
#[case::empty(&[], hex!("51b572209083576ea221c27e62b4e22063257571ccb6cc3dc3cd17eb67584eba"))]
#[case::single_zero(&[0u8], hex!("ad4015a1059886781a796efe2326c9e6beb07bcf847f4897e0f8a3fa24004024"))]
fn known_hash(#[case] input: &[u8], #[case] expected: [u8; 32]) {
  let got = hash(input);
  assert_eq!(got, expected);
}
