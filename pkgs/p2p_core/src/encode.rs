//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Encoding utilities for P2P message serialization.

use crate::prelude::*;

use core::fmt;

pub use dash_primitives::codec::{BufferDecoder, VecEncoder};

/// Maximum buffered P2P message payload (4 MB).
pub(crate) const MAX_P2P_PAYLOAD: usize = 4_000_000;

/// Encodes a `usize` as a Bitcoin-style CompactSize integer.
pub(crate) fn encode_compact_size(value: usize, buf: &mut Vec<u8>) {
  match value {
    0..=0xFC => buf.push(value as u8),
    0xFD..=0xFFFF => {
      buf.push(0xFD);
      buf.extend_from_slice(&(value as u16).to_le_bytes());
    }
    0x1_0000..=0xFFFF_FFFF => {
      buf.push(0xFE);
      buf.extend_from_slice(&(value as u32).to_le_bytes());
    }
    _ => {
      buf.push(0xFF);
      buf.extend_from_slice(&(value as u64).to_le_bytes());
    }
  }
}

/// Error wrapper for cursor-based decode operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireDecodeError(pub(crate) alloc::string::String);

impl fmt::Display for WireDecodeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(&self.0)
  }
}

impl From<dash_primitives::codec::DecodeError> for WireDecodeError {
  fn from(e: dash_primitives::codec::DecodeError) -> Self {
    Self(alloc::format!("{e}"))
  }
}

impl From<dash_primitives::error::DecodeError> for WireDecodeError {
  fn from(e: dash_primitives::error::DecodeError) -> Self {
    Self(alloc::format!("{e}"))
  }
}
