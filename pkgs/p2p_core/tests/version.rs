//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for Version (version message).

mod util;

use dash_p2p_core::msg::Version;

#[test]
fn version() {
  util::check_corpus::<Version>("version", "version");
}
