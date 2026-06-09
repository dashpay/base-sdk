//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpServTx service-update payload (type 2).

use super::proregtx::NetInfo;
use crate::codec::impl_payload;
use crate::prelude::*;
use crate::script::Script;
use crate::support::CService;
use crate::tx_types::MnType;
use crate::validation::{check_sptx_netinfo, ProTxInvalid, PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR};
use crate::{InputsHash, TxHash};

use dash_types::codec::{BaseCodec, DecodeError, NumCodec};
use dash_types::{BlsSignatureBytes, PlatformNodeId};

use core::fmt;

/// ProUpServTx -- update MN service addr (type 2).
///
/// - v1: LegacyBLS (no mn_type field)
/// - v2: BasicBLS (adds mn_type)
/// - v3: ExtAddr (extended network info)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ProUpServTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// v2+ only; defaults to Regular for v1.
  pub mn_type: MnType,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Legacy CService or extended NetInfo.
  pub net_info: NetInfo,
  /// Operator payout script.
  pub script_operator_payout: Script,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Platform node id (Evo only).
  pub platform_node_id: Option<PlatformNodeId>,
  /// Platform P2P port (Evo + version < 3 only).
  pub platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  pub platform_http_port: Option<u16>,
  /// Operator BLS signature.
  pub sig: BlsSignatureBytes,
}

impl_payload!(ProUpServTx);

impl BaseCodec for ProUpServTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;

    let mn_type = if version >= 2 {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };

    let pro_tx_hash = TxHash::decode(data)?;
    let net_info = if version >= 3 {
      let raw: Vec<u8> = Vec::decode(data)?;
      NetInfo::Extended(crate::support::ExtendedNetInfo::decode(&mut &raw[..])?)
    } else {
      NetInfo::Legacy(CService::decode(data)?)
    };
    let script_operator_payout = Script::decode(data)?;
    let inputs_hash = InputsHash::decode(data)?;
    let (platform_node_id, platform_p2p_port, platform_http_port) = if mn_type == MnType::Evo {
      let node_id = PlatformNodeId::decode(data)?;
      if version < 3 {
        (Some(node_id), Some(u16::decode(data)?), Some(u16::decode(data)?))
      } else {
        (Some(node_id), None, None)
      }
    } else {
      (None, None, None)
    };

    Ok(Self {
      version,
      mn_type,
      pro_tx_hash,
      net_info,
      script_operator_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: BlsSignatureBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    if self.version >= 2 {
      self.mn_type.to_base().encode(buf);
    }
    self.pro_tx_hash.encode(buf);
    // Branch on version to match the decode path. Validation
    // guarantees the variant matches the version.
    if self.version >= 3 {
      if let NetInfo::Extended(ext) = &self.net_info {
        let mut inner = Vec::new();
        ext.encode(&mut inner);
        inner.encode(buf);
      }
    } else if let NetInfo::Legacy(svc) = &self.net_info {
      svc.encode(buf);
    }
    self.script_operator_payout.encode(buf);
    self.inputs_hash.encode(buf);
    if self.mn_type == MnType::Evo {
      self.platform_node_id.unwrap_or_default().encode(buf);
      if self.version < 3 {
        self.platform_p2p_port.unwrap_or(0).encode(buf);
        self.platform_http_port.unwrap_or(0).encode(buf);
      }
    }
    self.sig.encode(buf);
  }
}

impl ProUpServTx {
  /// Validates structural invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self) -> Result<(), ProTxInvalid> {
    if self.version == 0 {
      return Err(ProTxInvalid::BadVersion { version: self.version });
    }

    if self.mn_type == MnType::Evo && self.version < PROTX_VERSION_BASIC_BLS {
      return Err(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version == PROTX_VERSION_EXT_ADDR) {
      return Err(ProTxInvalid::NetInfoVersionMismatch);
    }

    match &self.net_info {
      NetInfo::Extended(ext) => {
        if ext.entries.is_empty() {
          return Err(ProTxInvalid::NetInfoEmpty);
        }
        if let Some(e) = check_sptx_netinfo(&ext.entries, self.mn_type, self.version == PROTX_VERSION_EXT_ADDR) {
          return Err(e);
        }
      }
      NetInfo::Legacy(svc) => {
        if svc.addr.is_null() && svc.port == 0 {
          return Err(ProTxInvalid::NetInfoEmpty);
        }
      }
    }

    Ok(())
  }
}

impl fmt::Display for ProUpServTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpServTx {{ v{}, mn_type: {} }}", self.version, self.mn_type,)
  }
}
