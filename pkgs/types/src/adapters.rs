//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridging modules for foreign crate types.

/// Bridges an upstream type into [`BaseCodec`].
macro_rules! adapt_codec {
  (<$gen:ident>, $ty:ty) => {
    impl<$gen> $crate::codec::BaseCodec for $ty {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::codec::DecodeError> {
        let n = $crate::codec::read_compact_size(data, data.len())?;
        let bytes = $crate::codec::read_bytes(data, n)?;
        Ok(Self::from_bytes(bytes.to_vec()))
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        let bytes = self.as_bytes();
        $crate::codec::write_compact_size(bytes.len(), buf);
        buf.extend_from_slice(bytes);
      }
    }
  };
  ($ty:ty, $len:expr) => {
    impl $crate::codec::BaseCodec for $ty {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::codec::DecodeError> {
        let bytes = $crate::codec::read_bytes(data, $len)?;
        let mut arr = [0u8; $len];
        arr.copy_from_slice(bytes);
        Ok(Self::from_byte_array(arr))
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        buf.extend_from_slice(&self.to_byte_array());
      }
    }
  };
}

#[cfg(feature = "bitcoin-primitives")]
pub mod bitcoin_primitives {
  use crate::codec::{ArrayBuf, BaseCodec, EncodeBuf, Hashable};
  use crate::make_bytes;
  use crate::prelude::*;

  use base58ck::encode_check;
  use bitcoin_hashes::{ripemd160, sha256};
  use bitcoin_primitives::script::{ScriptBuf, ScriptHashableTag};

  adapt_codec!(<T>, ScriptBuf<T>);

  // nosemgrep: types-macro-no-codec
  make_bytes! {
    /// 20-byte script hash.
    ScriptHash, 20
  }

  impl ScriptHash {
    /// Encode as a Base58Check address with the given version prefix.
    pub fn to_base58c(&self, prefix: u8) -> String {
      let mut buf = ArrayBuf::<21>::new();
      buf.push(prefix);
      self.encode(&mut buf);
      encode_check(&buf.into_array())
    }
  }

  impl<T: ScriptHashableTag> Hashable for ScriptBuf<T> {
    type Hash = ScriptHash;

    fn hash(&self) -> ScriptHash {
      ScriptHash::from(*ripemd160::Hash::hash(sha256::Hash::hash(self.as_bytes()).as_ref()).as_byte_array())
    }
  }

  #[cfg(test)]
  #[expect(clippy::unwrap_used, reason = "test code")]
  mod tests {
    use crate::codec::BaseCodec;
    use crate::prelude::*;

    use bitcoin_primitives::script::{ScriptBuf, ScriptPubKeyTag};
    use rstest::*;

    #[rstest]
    fn codec_roundtrip() {
      let script = ScriptBuf::<ScriptPubKeyTag>::from_bytes(alloc::vec![0x76, 0xa9, 0x14, 0xff]);
      let mut buf = Vec::new();
      script.encode(&mut buf);
      let decoded = ScriptBuf::<ScriptPubKeyTag>::decode(&mut buf.as_slice()).unwrap();
      assert_eq!(decoded.as_bytes(), script.as_bytes());
    }

    #[rstest]
    fn codec_is_length_prefixed() {
      let script = ScriptBuf::<ScriptPubKeyTag>::from_bytes(alloc::vec![0x51, 0x52]);
      let mut buf = Vec::new();
      script.encode(&mut buf);
      assert_eq!(buf, alloc::vec![2, 0x51, 0x52]);
    }
  }
}
