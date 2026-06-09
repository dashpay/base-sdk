//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for governance trigger (superblock) objects.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use rstest::rstest;

#[rstest]
fn decode_and_hash() {
  util::gov::check("triggers");
}
