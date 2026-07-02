//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Genesis validation test.

use dash_params::types::ChainParams;
use dash_primitives::{Block, BlockHash, MerkleRoot};
use dash_types::codec::Hashable;
use hex_literal::hex;
use rstest::rstest;

#[rstest]
#[case::mainnet(
  dash_params::main::genesis(),
  &dash_params::main::PARAMS,
  MerkleRoot::new(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7")),
)]
#[case::testnet(
  dash_params::test3::genesis(),
  &dash_params::test3::PARAMS,
  MerkleRoot::new(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7")),
)]
#[case::regtest(
  dash_params::regtest::genesis(),
  &dash_params::regtest::PARAMS,
  MerkleRoot::new(hex!("e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7")),
)]
fn genesis_block_hash_matches(
  #[case] genesis: Block,
  #[case] params: &ChainParams,
  #[case] expected_merkle_root: MerkleRoot,
) {
  // The merkle root stored in the header must match the expected
  // value (txid of the single coinbase transaction).
  assert_eq!(genesis.header.merkle_root, expected_merkle_root);
  let (root, mutated) = genesis.merkle();
  assert_eq!(root, expected_merkle_root);
  assert!(!mutated);

  // PoW hash the 80-byte header and verify it matches the genesis
  // hash declared in the consensus parameters.
  let expected = BlockHash::from(params.consensus.hash_genesis_block);
  assert_eq!(genesis.header.hash(), expected);
}
