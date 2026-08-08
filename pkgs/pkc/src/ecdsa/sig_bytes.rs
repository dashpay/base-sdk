//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 signature byte bag.

use crate::prelude::*;

use bitcoin_hashes::sha256d;
use cfg_if::cfg_if;
use dash_num::Hash256;
use dash_types::codec::{read_bytes, BaseCodec, DecodeError, EncodeBuf, Hashable};
use dash_types::{impl_type, type_cvrt, CompactSize, TypeId};

use core::fmt;

/// Raw secp256k1 signature (r || s) length.
pub const ECDSA_SIG_LEN: usize = 64;

/// Raw compact ECDSA signature bytes (r || s, unvalidated scalars).
#[derive(Clone, Copy, Eq, Hash, PartialEq, TypeId)]
pub struct EcdsaSigBytes([u8; ECDSA_SIG_LEN]);

impl BaseCodec for EcdsaSigBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let n = CompactSize::decode(data)?.into_len(ECDSA_SIG_LEN)?;
    if n != ECDSA_SIG_LEN {
      return Err(DecodeError::BadLen {
        expected: vec![ECDSA_SIG_LEN],
        actual: n,
      });
    }
    let mut arr = [0u8; ECDSA_SIG_LEN];
    arr.copy_from_slice(read_bytes(data, n)?);
    Ok(Self(arr))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.0.len()).encode(buf);
    buf.extend_from_slice(&self.0); // nosemgrep: codec-no-raw-extend
  }
}

impl_type!(EcdsaSigBytes);

impl Hashable for EcdsaSigBytes {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    Hash256::from_bytes(sha256d::Hash::hash(&self.0).to_byte_array())
  }
}

impl EcdsaSigBytes {
  /// Borrow the raw inner bytes.
  pub const fn as_bytes(&self) -> &[u8; ECDSA_SIG_LEN] {
    &self.0
  }

  /// Copy out the raw inner bytes.
  pub const fn to_bytes(&self) -> [u8; ECDSA_SIG_LEN] {
    self.0
  }
}

impl fmt::Debug for EcdsaSigBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSigBytes({self})")
  }
}

impl fmt::Display for EcdsaSigBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}

type_cvrt!(From<[u8; ECDSA_SIG_LEN]> for EcdsaSigBytes, |bytes| {
  Self(*bytes)
});

cfg_if! {
  if #[cfg(feature = "serde")] {
    use dash_types::serialize::hex as serde_hex;
    use serde::de::Error as DeError;
    use serde::{Deserializer, Serializer};

    impl ::serde::Serialize for EcdsaSigBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_hex::serialize(&self.0, serializer)
      }
    }

    impl<'de> ::serde::Deserialize<'de> for EcdsaSigBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_hex::deserialize(deserializer)?
          .as_slice()
          .try_into()
          .map(Self)
          .map_err(|_| DeError::custom("invalid compact signature length"))
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{EcdsaSigBytes, ECDSA_SIG_LEN};
  use crate::prelude::*;

  use dash_types::codec::BaseCodec;
  use rstest::*;

  #[rstest]
  fn codec_is_length_prefixed() {
    let sb = EcdsaSigBytes::from([0xab; ECDSA_SIG_LEN]);
    let mut buf = Vec::new();
    sb.encode(&mut buf);
    assert_eq!(buf.len(), ECDSA_SIG_LEN + 1);
    assert_eq!(buf[0] as usize, ECDSA_SIG_LEN);
    let decoded = EcdsaSigBytes::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(decoded, sb);
  }

  #[rstest]
  fn roundtrip() {
    let bytes = [0x42; ECDSA_SIG_LEN];
    let sb = EcdsaSigBytes::from(bytes);
    assert_eq!(sb.as_bytes(), &bytes);
    assert_eq!(sb.to_bytes(), bytes);
  }
}
