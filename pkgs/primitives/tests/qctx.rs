//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for FinalCommitment (LLMQ commitment).

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::FinalCommitment;
use rstest::rstest;

#[rstest]
fn corpus() {
  util::payload::check::<FinalCommitment>("qctx", "qctx");
}
