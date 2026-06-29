//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared types and macros for the Dash SDK.

#![no_std]

extern crate alloc;
extern crate self as dash_types;
#[cfg(feature = "std")]
extern crate std;

mod entity;
mod hex;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod uint;

pub mod codec;
#[cfg(feature = "serde")]
pub mod serialize;

pub use dash_types_marker::Unencodable;
pub use entity::{BufferDecoder, VecEncoder, MAX_SER_SIZE};

#[doc(hidden)]
pub mod __private {
  pub use bitcoin_consensus_encoding;
  #[cfg(feature = "serde")]
  pub use hex_conservative;
}

/// Generates \`From<T>\` + \`From<&T>\` (or \`TryFrom\` equivalents).
/// The closure body receives \`&$src\`; the owned impl delegates.
#[macro_export]
macro_rules! type_cvrt {
  (From<$src:ty> for $dst:ty, |$v:ident| $body:expr) => {
    impl From<&$src> for $dst {
      fn from($v: &$src) -> Self {
        $body
      }
    }
    impl From<$src> for $dst {
      fn from(v: $src) -> Self {
        Self::from(&v)
      }
    }
  };
  (TryFrom<$src:ty> for $dst:ty, $err:ty, |$v:ident| $body:expr) => {
    impl TryFrom<&$src> for $dst {
      type Error = $err;
      fn try_from($v: &$src) -> Result<Self, Self::Error> {
        $body
      }
    }
    impl TryFrom<$src> for $dst {
      type Error = $err;
      fn try_from(v: $src) -> Result<Self, Self::Error> {
        Self::try_from(&v)
      }
    }
  };
}
