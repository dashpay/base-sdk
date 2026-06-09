//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for GetHeaders2 and Headers2 (DIP-0025).

mod util;

use dash_p2p_core::msg::{GetHeaders2, Headers2};

#[test]
fn getheaders2() {
  util::check_corpus::<GetHeaders2>("headers2", "getheaders2");
}

#[test]
fn headers2() {
  util::check_corpus::<Headers2>("headers2", "headers2");
}
