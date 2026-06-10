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

mod corpus;
mod lambda;
mod prelude;

#[cfg(feature = "std")]
pub use corpus::load_corpus_file;
pub use corpus::CorpusEntry;
#[cfg(all(feature = "std", feature = "serde"))]
pub use corpus::{assert_serde_rt, read_corpus, write_corpus};
pub use lambda::{check_sptx, check_tx, check_wire};
