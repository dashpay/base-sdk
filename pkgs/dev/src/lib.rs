//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Development and test utilities.

#![no_std]
#![expect(clippy::panic, reason = "development crate")]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod encode;
mod lambda;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

pub use encode::{arr_from_hex, vec_from_hex};
pub use lambda::{check_sptx, check_tx, check_wire};

cfg_if::cfg_if! {
  if #[cfg(all(feature = "std", feature = "serde"))] {
    mod corpus;

    pub use crate::corpus::{assert_serde_rt, Corpus};
  }
}
