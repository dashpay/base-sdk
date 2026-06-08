//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for data (OP_RETURN) transactions.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use rstest::rstest;

#[rstest]
fn corpus() {
  util::transaction::check("data", "data");
}
