//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Stable type identifiers.

// nosemgrep: use-pub-roots-only
pub use dash_types_marker::{TypeId, Unencodable};

/// Odd, so multiplying by it is a bijection over `u32` and no two
/// accumulators can collapse into one. The golden ratio constant.
const TYPE_ID_MIX_A: u32 = 0x9E37_79B1;

/// Odd as well, and distinct from [`TYPE_ID_MIX_A`] so the two rounds of
/// multiplication do not compose into one. XXH32's second prime.
const TYPE_ID_MIX_B: u32 = 0x85EB_CA77;

/// Stable identifier derived from the type name and its parameters.
pub trait TypeId {
  const TYPE_ID: u32;
}

/// Carries type parameters into an identifier.
///
/// Rotating only the accumulator keeps the fold order-sensitive, so `Foo<A, B>`
/// and `Foo<B, A>` differ.
#[doc(hidden)]
#[must_use]
pub const fn mix(acc: u32, param: u32) -> u32 {
  let mut h = acc.rotate_left(5).wrapping_add(TYPE_ID_MIX_A) ^ param.wrapping_mul(TYPE_ID_MIX_B);
  h = h.wrapping_mul(TYPE_ID_MIX_A);
  h ^= h >> 15;
  h = h.wrapping_mul(TYPE_ID_MIX_B);
  h ^= h >> 13;
  h
}

#[cfg(test)]
mod tests {
  use super::{mix, TypeId};

  use rstest::*;

  use core::marker::PhantomData;

  /// Pins mixing outputs given set of fixed inputs, wire-critical.
  #[rstest]
  #[case(0x0000_0000, 0x0000_0000, 0x2E23_CDE1)]
  #[case(0x0000_0001, 0x0000_0000, 0x547E_AC0B)]
  #[case(0x0000_0000, 0x0000_0001, 0x6B2D_FE60)]
  #[case(0xDEAD_BEEF, 0x1234_5678, 0x1807_3B33)]
  fn mix_is_pinned(#[case] acc: u32, #[case] param: u32, #[case] want: u32) {
    assert_eq!(mix(acc, param), want);
  }

  #[rstest]
  #[case(1, 2)]
  #[case(0xDEAD_BEEF, 0x1234_5678)]
  fn mix_is_order_sensitive(#[case] a: u32, #[case] b: u32) {
    assert_ne!(mix(a, b), mix(b, a));
    assert_ne!(mix(mix(0, a), b), mix(mix(0, b), a));
  }

  #[rstest]
  #[case(0, 0)]
  #[case(1, 2)]
  #[case(0xDEAD_BEEF, 0x1234_5678)]
  fn mix_moves_away_from_both_inputs(#[case] acc: u32, #[case] param: u32) {
    let mixed = mix(acc, param);
    assert_ne!(mixed, acc);
    assert_ne!(mixed, param);
  }

  #[derive(TypeId)]
  struct MixA;

  #[derive(TypeId)]
  struct MixB;

  trait MixMark {}
  impl MixMark for MixA {}
  impl MixMark for MixB {}

  #[derive(TypeId)]
  struct MixPair<X: MixMark, Y: MixMark>(PhantomData<(X, Y)>);

  /// Bare names keep the XXH32 of stringized type name, mustn't be shifted.
  #[rstest]
  fn plain_derive_hashes_the_bare_name() {
    assert_eq!(MixA::TYPE_ID, 0x8B87_3C41);
    assert_eq!(MixB::TYPE_ID, 0x053E_1B33);
  }

  /// Each instantiation gets its own id, sensitive to argument order.
  #[rstest]
  fn generic_derive_folds_the_type_parameters() {
    assert_eq!(MixPair::<MixA, MixB>::TYPE_ID, 0xEE0D_108A);
    assert_eq!(MixPair::<MixB, MixA>::TYPE_ID, 0x08C7_53E2);
    assert_ne!(MixPair::<MixA, MixA>::TYPE_ID, MixPair::<MixB, MixB>::TYPE_ID);
    assert_ne!(MixPair::<MixA, MixB>::TYPE_ID, MixA::TYPE_ID);
  }
}
