//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared macro definitions.

use crate::prelude::*;
use crate::P2pDecodeError;

use bitcoin_consensus_encoding::{decode_from_slice, Decode, Decoder};

/// Decode from slice, mapping the error.
pub(crate) fn decode_msg<T: Decode>(payload: &[u8]) -> Result<T, P2pDecodeError>
where
  <T::Decoder as Decoder>::Error: core::fmt::Display,
{
  decode_from_slice(payload).map_err(|e| P2pDecodeError::Consensus(format!("{e}")))
}

/// Generates `P2pMsg` definitions for every given valid message
macro_rules! define_p2p {
  (
    // Fully-parsed messages with a typed payload.
    parsed {
      $(
        $(#[$p_doc:meta])*
        $p_variant:ident ( $p_type:ty ) => $p_cmd:ident
      ),* $(,)?
    }
    // Fully-parsed messages with an empty payload.
    parsed_empty {
      $(
        $(#[$pe_doc:meta])*
        $pe_variant:ident => $pe_cmd:ident
      ),* $(,)?
    }
    // Recognised but not-yet-implemented (raw `Vec<u8>` payload).
    stub {
      $(
        $(#[$s_doc:meta])*
        $s_variant:ident => $s_cmd:ident
      ),* $(,)?
    }
    // Recognised but not-yet-implemented (empty payload).
    stub_empty {
      $(
        $(#[$se_doc:meta])*
        $se_variant:ident => $se_cmd:ident
      ),* $(,)?
    }
  ) => {
    /// A P2P network message.
    #[derive(Clone, Debug, Eq, PartialEq, Unencodable)]
    #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
    pub enum P2pMsg {
      $( $(#[$p_doc])* $p_variant($p_type), )*
      $( $(#[$pe_doc])* $pe_variant, )*
      $( $(#[$s_doc])* $s_variant(Vec<u8>), )*
      $( $(#[$se_doc])* $se_variant, )*
    }

    impl P2pMsg {
      /// Returns the 12-byte command string for this message.
      pub fn command(&self) -> CommandString {
        match self {
          $( Self::$p_variant(_) => CommandString::$p_cmd, )*
          $( Self::$pe_variant => CommandString::$pe_cmd, )*
          $( Self::$s_variant(_) => CommandString::$s_cmd, )*
          $( Self::$se_variant => CommandString::$se_cmd, )*
        }
      }

      /// Returns the V2 short ID for this message, if one exists.
      pub fn short_id(&self) -> Option<ShortId> {
        ShortId::from_command(&self.command())
      }

      /// Returns `true` when the message is recognised but not decoded.
      pub fn is_stub(&self) -> bool {
        match self {
          $( Self::$p_variant(_) => false, )*
          $( Self::$pe_variant => false, )*
          $( Self::$s_variant(_) => true, )*
          $( Self::$se_variant => true, )*
        }
      }

      /// Decodes a message from its command string and raw payload.
      pub fn decode_payload(
        cmd: &CommandString,
        payload: &[u8],
      ) -> Result<Self, crate::P2pDecodeError> {
        let raw = || Vec::from(payload);
        let msg = match *cmd {
          $( CommandString::$p_cmd => Self::$p_variant(crate::macros::decode_msg(payload)?), )*
          $( CommandString::$pe_cmd => Self::$pe_variant, )*
          $( CommandString::$s_cmd => Self::$s_variant(raw()), )*
          $( CommandString::$se_cmd => Self::$se_variant, )*
          _ => return Err(crate::P2pDecodeError::UnknownCommand { bytes: *cmd.as_bytes() }),
        };
        Ok(msg)
      }

      /// Encodes this message's payload (without command/short-ID framing).
      pub fn encode_payload(&self, buf: &mut Vec<u8>) {
        match self {
          $(
            Self::$p_variant(m) => {
              buf.extend_from_slice(&encoding::encode_to_vec(m));
            }
          )*
          $( Self::$pe_variant => {} )*
          $( Self::$s_variant(raw) => buf.extend_from_slice(raw), )* // nosemgrep: codec-no-raw-extend
          $( Self::$se_variant => {} )*
        }
      }
    }
  };
}
