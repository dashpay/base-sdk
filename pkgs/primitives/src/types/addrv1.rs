//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy ADDRv1 address and service types.

use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError};
use dash_types::impl_type;

dash_types::make_bytes! {
  /// ADDRv1 IPv4-mapped IPv6 address (16 bytes).
  AddrV1, 16
}

/// Legacy network address (ADDRv1 format, 18 bytes).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ServiceV1 {
  /// 16-byte address (IPv4-mapped IPv6 or native IPv6).
  pub addr: AddrV1,
  /// Network port (big-endian on the wire).
  pub port: u16,
}

impl_type!(ServiceV1);

impl BaseCodec for ServiceV1 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      addr: AddrV1::decode(data)?,
      port: codec::read_u16_be(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}
