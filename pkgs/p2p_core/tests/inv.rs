//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for Inv (inv message).

mod util;

use dash_p2p_core::msg::Inv;

#[test]
fn inv() {
  util::check_corpus::<Inv>("inv", "inv");
}
