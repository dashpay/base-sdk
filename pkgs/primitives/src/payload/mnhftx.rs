//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! MnHardFork hard-fork signal (type 7).

use crate::codec::codec_payload;
use crate::validation::VERSIONBITS_NUM_BITS;
use crate::QuorumHash;

use dash_types::codec::Checkable;
use dash_types::BlsSignatureBytes;

use core::fmt;

/// MnHardFork -- hard-fork signal (type 7).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnHardFork {
  /// Payload version.
  pub version: u8,
  /// Feature bit being activated.
  pub version_bit: u8,
  /// Quorum hash.
  pub quorum_hash: QuorumHash,
  /// Quorum BLS signature.
  pub sig: BlsSignatureBytes,
}

codec_payload!(MnHardFork {
  version,
  version_bit,
  quorum_hash,
  sig,
});

/// MNHF signal validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MnHardForkInvalid {
  /// `bad-mnhf-version`
  BadVersion { version: u8 },
  /// `bad-mnhf-nbit-out-of-bounds`
  VersionBitOutOfBounds { bit: u8 },
}

impl core::fmt::Display for MnHardForkInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-mnhf-version: {version}"),
      Self::VersionBitOutOfBounds { bit } => write!(f, "bad-mnhf-nbit-out-of-bounds: {bit}"),
    }
  }
}

impl Checkable for MnHardFork {
  type Error = MnHardForkInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 1 {
      return Some(MnHardForkInvalid::BadVersion { version: self.version });
    }

    if self.version_bit >= VERSIONBITS_NUM_BITS {
      return Some(MnHardForkInvalid::VersionBitOutOfBounds { bit: self.version_bit });
    }

    None
  }
}

impl fmt::Display for MnHardFork {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "MnHardFork {{ v{}, bit: {} }}", self.version, self.version_bit,)
  }
}
