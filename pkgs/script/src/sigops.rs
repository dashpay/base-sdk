//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signature operations count.

use crate::opcode::Opcode;

const MAX_PUBKEYS: usize = 20;

/// Count legacy signature operations in a script.
///
/// Counts `OP_CHECKMULTISIG` (weighted by `MAX_PUBKEYS_PER_MULTISIG`),
/// `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` and `OP_CHECKMULTISIGVERIFY`.
pub fn legacy_sigop_count(script: &[u8]) -> usize {
  let mut count: usize = 0;
  let mut i = 0;
  while i < script.len() {
    let byte = script[i];
    if Opcode::is_direct_push(byte) {
      // skip over pushed data
      i = i.saturating_add(1).saturating_add(byte as usize);
      continue;
    }
    match Opcode::from_base(byte) {
      Opcode::CheckSig | Opcode::CheckSigVerify => count = count.saturating_add(1),
      Opcode::CheckMultiSig | Opcode::CheckMultiSigVerify => {
        count = count.saturating_add(MAX_PUBKEYS);
      }
      // A push whose length header is cut short ends the scan: the bytes that
      // follow are a truncated operand rather than opcodes, so nothing past
      // this point counts as a sigop.
      Opcode::PushData1 => match script.get(i + 1) {
        Some(&n) => {
          i = i.saturating_add(2).saturating_add(n as usize);
          continue;
        }
        None => break,
      },
      Opcode::PushData2 => match script.get(i + 1..i + 3) {
        Some(&[lo, hi]) => {
          let n = u16::from_le_bytes([lo, hi]);
          i = i.saturating_add(3).saturating_add(n as usize);
          continue;
        }
        _ => break,
      },
      Opcode::PushData4 => match script.get(i + 1..i + 5) {
        Some(&[a, b, c, d]) => {
          let n = u32::from_le_bytes([a, b, c, d]);
          i = i.saturating_add(5).saturating_add(n as usize);
          continue;
        }
        _ => break,
      },
      _ => {}
    }
    i += 1;
  }
  count
}

#[cfg(test)]
mod tests {
  use super::legacy_sigop_count;

  use hex_conservative::hex;
  use rstest::rstest;

  #[rstest]
  #[case::empty(&[], 0)]
  #[case::checksig(&[0xac], 1)]
  #[case::checksigverify(&[0xad], 1)]
  #[case::checkmultisig(&[0xae], 20)]
  #[case::checkmultisigverify(&[0xaf], 20)]
  #[case::multisig_always_20(&hex!("5152ae"), 20)]
  #[case::multisig_then_checksig(
    &hex!(concat!(
      "51",
      "1400000000000000000000000000000000000000001400000000000000000000000000000000000000",
      "52ae",
      "63ac68",
    )),
    21,
  )]
  #[case::p2pkh(&hex!("76a914000000000000000000000000000000000000000088ac"), 1)]
  #[case::if_checksig_endif(&hex!("63ac68"), 1)]
  #[case::skip_direct_push(&hex!("02acac"), 0)]
  #[case::skip_pushdata1(&hex!("4c01ac"), 0)]
  #[case::skip_pushdata2(&hex!("4d0100ac"), 0)]
  #[case::skip_pushdata4(&hex!("4e01000000ac"), 0)]
  // A truncated push header ends the scan, so trailing bytes that would read
  // as OP_CHECKSIG are operand and go uncounted.
  #[case::truncated_pushdata1(&hex!("4c"), 0)]
  #[case::truncated_pushdata2(&hex!("4dac"), 0)]
  #[case::truncated_pushdata4(&hex!("4eacacac"), 0)]
  // Sigops before the truncation still count; those after it do not.
  #[case::checksig_then_truncated_pushdata2(&hex!("ac4dac"), 1)]
  #[case::checksig_then_truncated_pushdata4(&hex!("ac4eacacac"), 1)]
  fn sigop_count(#[case] script: &[u8], #[case] expected: usize) {
    assert_eq!(legacy_sigop_count(script), expected);
  }
}
