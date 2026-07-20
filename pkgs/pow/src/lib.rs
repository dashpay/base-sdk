//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof-of-work hash used by Dash.
//!
//! Chains eleven 512-bit hash algorithms (Blake, BMW, Groestl, Skein, JH,
//! Keccak, Luffa, CubeHash, SHAvite, SIMD, Echo) and truncates the final output
//! to 256 bits.

#![no_std]
#![cfg_attr(feature = "simd", feature(portable_simd))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod blake;
mod bmw;
mod cubehash;
mod echo;
mod groestl;
mod jh;
mod keccak;
mod luffa;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod shavite;
mod simd_hash;
mod skein;
mod util;

#[cfg(feature = "std")]
pub mod worker;

#[doc(hidden)]
pub mod __private {
  pub mod blake {
    pub use crate::blake::*;
  }
  pub mod bmw {
    pub use crate::bmw::*;
  }
  pub mod cubehash {
    pub use crate::cubehash::*;
  }
  pub mod echo {
    pub use crate::echo::*;
  }
  pub mod groestl {
    pub use crate::groestl::*;
  }
  pub mod jh {
    pub use crate::jh::*;
  }
  pub mod keccak {
    pub use crate::keccak::*;
  }
  pub mod luffa {
    pub use crate::luffa::*;
  }
  pub mod shavite {
    pub use crate::shavite::*;
  }
  pub mod simd_hash {
    pub use crate::simd_hash::*;
  }
  pub mod skein {
    pub use crate::skein::*;
  }
}

/// Computes the Dash proof-of-work hash.
pub fn hash(data: &[u8]) -> dash_num::Hash256 {
  let h = blake::hash512(data);
  let h = bmw::hash512(h.as_ref());
  let h = groestl::hash512(h.as_ref());
  let h = skein::hash512(h.as_ref());
  let h = jh::hash512(h.as_ref());
  let h = keccak::hash512(h.as_ref());
  let h = luffa::hash512(h.as_ref());
  let h = cubehash::hash512(h.as_ref());
  let h = shavite::hash512(h.as_ref());
  let h = simd_hash::hash512(h.as_ref());
  let h = echo::hash512(h.as_ref());
  let mut out = [0u8; 32];
  out.copy_from_slice(&h.as_bytes()[..32]);
  dash_num::Hash256::from(out)
}
