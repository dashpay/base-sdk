//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network parameters for Dash (mainnet, testnet3, regtest).

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod prelude;

pub mod types;

#[path = "mainnet.rs"]
pub mod main;

pub mod test3;

pub mod regtest;
