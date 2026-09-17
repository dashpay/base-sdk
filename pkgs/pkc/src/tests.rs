//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common test definitions.

#[cfg(feature = "bls")]
pub mod bls {
  use dash_pkc::bls::BlsShareId;
  use dash_types::Numeric;

  use alloc::vec::Vec; // nosemgrep: prelude-no-use-alloc

  /// Build a participant id whose field element is `i`.
  pub fn make_id(i: u32) -> BlsShareId {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&i.to_be_bytes());
    BlsShareId::from_lendian(bytes)
  }

  /// Build `n` sequential participant ids `1..=n`.
  pub fn sequential_ids(n: usize) -> Vec<BlsShareId> {
    (1..=n).map(|i| make_id(i as u32)).collect()
  }

  /// Build a distinct 32-byte IKM from an index, for multi-signer runs.
  ///
  /// The index is carried in full, so a run of more than 256 signers gets that
  /// many distinct keys instead of wrapping at 256.
  pub fn test_ikm(i: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&(i as u64).to_be_bytes());
    ikm[24..].copy_from_slice(&(i as u64).wrapping_add(1).to_be_bytes());
    ikm
  }

  /// Build a distinct 32-byte message from an index, for multi-signer runs.
  ///
  /// As with [`test_ikm`], the index is carried in full to keep messages
  /// distinct past 256.
  pub fn test_msg(i: usize) -> [u8; 32] {
    let mut m = [0u8; 32];
    m[..8].copy_from_slice(&(i as u64).to_be_bytes());
    m[8..16].copy_from_slice(&(i as u64).wrapping_mul(7).to_be_bytes());
    m
  }
}

#[cfg(feature = "ecdsa")]
pub mod ecdsa {
  use hex_conservative::hex;

  /// Fixed secret key scalar the signing benchmarks run against.
  pub const ALICE_SK: [u8; 32] = hex!("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");

  /// Derive a distinct 32-byte message digest from an index.
  pub fn message_hash(i: u16) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = i as u8;
    h[31] = (i >> 8) as u8;
    h
  }
}

#[cfg(feature = "eddsa")]
pub mod eddsa {
  use hex_conservative::hex;

  /// The message the signing benchmarks cover.
  pub const MSG: &[u8] = b"dash platform node";

  /// The platform account secret at DIP-9 `m/9'/5'/3'/4'` for the
  /// "abandon ... about" mnemonic.
  pub const ALICE_SK: [u8; 32] = hex!("80035d9c2f89971a9c9fad826bba8be9328f1686ae555e912949c2c32800c379");

  /// The public key [`ALICE_SK`] derives to.
  pub const ALICE_PK: [u8; 32] = hex!("c352476b459846a552263aef12d35ce05d03ae9c6cfa380747d3700cdbb5c75f");
}
