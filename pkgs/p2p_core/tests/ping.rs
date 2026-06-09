//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for Ping and Pong messages.

mod util;

use dash_p2p_core::msg::{Ping, Pong};

#[test]
fn ping() {
  util::check_corpus::<Ping>("ping", "ping");
}

#[test]
fn pong() {
  util::check_corpus::<Pong>("ping", "pong");
}
