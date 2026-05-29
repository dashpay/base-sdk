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
    ::dash_types::impl_type!($ty, crate::codec::MAX_SPTX_PAYLOAD_SIZE);
  };
}
pub(crate) use impl_payload;
