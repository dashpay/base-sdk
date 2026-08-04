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
mod bitcoin_primitives {
  use bitcoin_primitives::script::ScriptBuf;

  adapt_codec!(<T>, ScriptBuf<T>);

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
