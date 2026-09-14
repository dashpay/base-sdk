//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compact difficulty target encoding tests.

use dash_num::{Arith256, CompactTarget};
use rstest::*;

/// Assert compact decode flags match expectations.
fn check_compact(compact: u32, expected_negative: bool, expected_overflow: bool) {
  let ct = CompactTarget::new(compact).expand();
  assert_eq!(
    ct.negative, expected_negative,
    "negative mismatch for compact {compact:#010x}"
  );
  assert_eq!(
    ct.overflow, expected_overflow,
    "overflow mismatch for compact {compact:#010x}"
  );
}

/// Zero-valued compacts that decode to zero, not
/// negative, not overflow.
#[rstest]
#[case(0x0000_0000)]
#[case(0x0012_3456)]
#[case(0x0100_3456)]
#[case(0x0200_0056)]
#[case(0x0300_0000)]
#[case(0x0400_0000)]
fn zero_value(#[case] compact: u32) {
  let ct = CompactTarget::new(compact).expand();
  assert_eq!(ct.value, Arith256::ZERO);
  assert_eq!(ct.value.compact(false), CompactTarget::new(0));
  check_compact(compact, false, false);
}

/// Sign bit set but word becomes zero after shift,
/// so negative stays false.
#[rstest]
#[case(0x0092_3456)]
#[case(0x0180_3456)]
#[case(0x0280_0056)]
#[case(0x0380_0000)]
#[case(0x0480_0000)]
fn sign_bit_but_zero_word(#[case] compact: u32) {
  let ct = CompactTarget::new(compact).expand();
  assert_eq!(ct.value, Arith256::ZERO);
  assert_eq!(ct.value.compact(false), CompactTarget::new(0));
  check_compact(compact, false, false);
}

#[rstest]
fn compact_01123456() {
  let ct = CompactTarget::new(0x01123456).expand();
  assert_eq!(ct.value, Arith256::from_u64(0x12));
  assert_eq!(ct.value.compact(false), CompactTarget::new(0x01120000));
  check_compact(0x01123456, false, false);
}

#[rstest]
fn compact_0x80_avoids_sign_bit() {
  let num = Arith256::from_u64(0x80);
  assert_eq!(num.compact(false), CompactTarget::new(0x02008000));
}

#[rstest]
fn compact_01fedcba() {
  // word=0x7edcba, size=1, shifted=0x7e, sign bit set
  let ct = CompactTarget::new(0x01fedcba).expand();
  assert_eq!(ct.value, Arith256::from_u64(0x7e));
  assert!(ct.negative);
  assert!(!ct.overflow);
  assert_eq!(ct.value.compact(true), CompactTarget::new(0x01fe0000));
}

/// Non-zero values with expected compact roundtrips.
#[rstest]
#[case(0x0212_3456, 0x1234, 0x0212_3400)]
#[case(0x0312_3456, 0x12_3456, 0x0312_3456)]
#[case(0x0412_3456, 0x1234_5600, 0x0412_3456)]
fn positive_values(#[case] compact: u32, #[case] expected_val: u64, #[case] expected_roundtrip: u32) {
  let ct = CompactTarget::new(compact).expand();
  assert_eq!(ct.value, Arith256::from_u64(expected_val));
  assert_eq!(ct.value.compact(false), CompactTarget::new(expected_roundtrip));
  check_compact(compact, false, false);
}

#[rstest]
fn compact_04923456_negative() {
  let ct = CompactTarget::new(0x04923456).expand();
  assert_eq!(ct.value, Arith256::from_u64(0x12345600));
  assert!(ct.negative);
  assert!(!ct.overflow);
  assert_eq!(ct.value.compact(true), CompactTarget::new(0x04923456));
}

#[rstest]
fn compact_05009234() {
  let ct = CompactTarget::new(0x05009234).expand();
  assert_eq!(ct.value, Arith256::from_u64(0x92340000));
  assert_eq!(ct.value.compact(false), CompactTarget::new(0x05009234));
  check_compact(0x05009234, false, false);
}

#[rstest]
fn compact_20123456() {
  let ct = CompactTarget::new(0x20123456).expand();
  assert_eq!(ct.value.compact(false), CompactTarget::new(0x20123456));
  check_compact(0x20123456, false, false);
}

#[rstest]
fn compact_ff123456_overflow() {
  let ct = CompactTarget::new(0xff123456).expand();
  assert!(!ct.negative);
  assert!(ct.overflow);
}

#[rstest]
#[case(0x0100_3456_u32, 0x00_u64)]
#[case(0x0112_3456_u32, 0x12_u64)]
#[case(0x0200_8000_u32, 0x80_u64)]
#[case(0x0500_9234_u32, 0x9234_0000_u64)]
#[case(0x0492_3456_u32, 0x00_u64)]
#[case(0x0412_3456_u32, 0x1234_5600_u64)]
fn target_from_compact_ported(#[case] n_bits: u32, #[case] target: u64) {
  let decoded = CompactTarget::new(n_bits).expand();
  // For negative-flagged values the target is 0.
  if decoded.negative {
    assert_eq!(Arith256::from_u64(target), Arith256::ZERO);
  } else {
    assert_eq!(decoded.value, Arith256::from_u64(target));
  }
}

/// CompactTarget display.
#[rstest]
fn display() {
  assert_eq!(format!("{}", CompactTarget::new(0x1d00ffff)), "0x1d00ffff");
}
