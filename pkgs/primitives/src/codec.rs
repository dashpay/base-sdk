//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for primitives payload types.

/// Maximum special-transaction payload size over the wire (10 KiB).
pub const MAX_SPTX_PAYLOAD_SIZE: usize = 10_240;

/// Generates `Encodable` + `Decodable` with payload size limit.
macro_rules! impl_payload {
  ($ty:ty) => {
    $crate::__private::dash_types::impl_type!($ty, crate::codec::MAX_SPTX_PAYLOAD_SIZE);
  };
}
pub(crate) use impl_payload;

/// Generates `BaseCodec` + `Encodable` + `Decodable` for flat structs.
#[macro_export]
macro_rules! codec_type {
  ($ty:ty { $($field:ident),+ $(,)? }) => {
    $crate::codec_type!($ty, $crate::__private::dash_types::MAX_SER_SIZE, { $($field),+ });
  };
  ($ty:ty, $max:expr, { $($field:ident),+ $(,)? }) => {
    impl $crate::__private::dash_types::codec::BaseCodec for $ty {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::__private::dash_types::codec::DecodeError> {
        Ok(Self {
          $($field: $crate::__private::dash_types::codec::BaseCodec::decode(data)?),+
        })
      }

      fn encode(&self, buf: &mut impl $crate::__private::dash_types::codec::EncodeBuf) {
        $($crate::__private::dash_types::codec::BaseCodec::encode(&self.$field, buf);)+
      }
    }

    $crate::__private::dash_types::impl_type!($ty, $max);
  };
}

/// Generates `BaseCodec` + `Encodable` + `Decodable` for flat structs
/// with payload size limit.
macro_rules! codec_payload {
  ($ty:ty { $($field:ident),+ $(,)? }) => {
    $crate::codec_type!($ty, crate::codec::MAX_SPTX_PAYLOAD_SIZE, { $($field),+ });
  };
}
pub(crate) use codec_payload;
