//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for MnListDiffPayload.

mod util;

use dash_p2p_core::primitives::mn_list::MnListDiffPayload;

#[test]
fn mnlistdiff() {
  util::check_corpus::<MnListDiffPayload>("mnlistdiff", "mnlistdiff");
}
