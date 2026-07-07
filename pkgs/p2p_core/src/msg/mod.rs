//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P message types and dispatch.

mod addr;
mod compact_filters;
mod gov;
mod headers;
mod headers2;
mod inv;
mod mn_list;
mod ping;
mod version;

use crate::command::CommandString;
use crate::prelude::*;
use crate::short_id::ShortId;

use bitcoin_consensus_encoding as encoding;
use dash_types::Unencodable;

pub use addr::{Addr, AddrV2Entry, AddrV2Msg, TimestampedAddr};
pub use compact_filters::{CFCheckpt, CFHeaders, CFilter, FilterType, GetCFCheckpt, GetCFHeaders, GetCFilters};
pub use gov::GovSync;
pub use headers::{GetHeaders, Headers};
pub use headers2::{CompressionState, GetHeaders2, Headers2};
pub use inv::{GetData, Inv, InvType, Inventory, NotFound};
pub use mn_list::{DeletedQuorum, GetMnListDiff, MnListDiff, MnListDiffPayload, QuorumClSig, SimplifiedMnListEntry};
pub use ping::{Ping, Pong};
pub use version::{ServiceFlags, UserAgent, UserAgentTooLong, Version, VersionAddr};

define_p2p! {
  parsed {
    /// Protocol version exchange.
    Version(Version) => VERSION,
    /// Keepalive request.
    Ping(Ping) => PING,
    /// Keepalive response.
    Pong(Pong) => PONG,
    /// V1 address list.
    Addr(Addr) => ADDR,
    /// BIP155 V2 address list.
    AddrV2(AddrV2Msg) => ADDRV2,
    /// Inventory announcement.
    Inv(Inv) => INV,
    /// Request specific inventory.
    GetData(GetData) => GETDATA,
    /// Inventory not found.
    NotFound(NotFound) => NOTFOUND,
    /// Request block headers.
    GetHeaders(GetHeaders) => GETHEADERS,
    /// Block headers.
    Headers(Headers) => HEADERS,
    /// Request compressed block headers.
    GetHeaders2(GetHeaders2) => GETHEADERS2,
    /// Compressed block headers.
    Headers2(Headers2) => HEADERS2,
    /// Request compact filters.
    GetCFilters(GetCFilters) => GETCFILTERS,
    /// Compact block filter.
    CFilter(CFilter) => CFILTER,
    /// Request compact filter headers.
    GetCFHeaders(GetCFHeaders) => GETCFHEADERS,
    /// Compact filter headers.
    CFHeaders(CFHeaders) => CFHEADERS,
    /// Request compact filter checkpoints.
    GetCFCheckpt(GetCFCheckpt) => GETCFCHECKPT,
    /// Compact filter checkpoints.
    CFCheckpt(CFCheckpt) => CFCHECKPT,
    /// Governance sync request.
    GovSync(GovSync) => GOVSYNC,
    /// Governance object.
    GovObj(dash_primitives::GovObject) => GOVOBJ,
    /// Governance vote.
    GovObjVote(dash_primitives::GovVote) => GOVOBJVOTE,
    /// Request MN list diff.
    GetMnListDiff(GetMnListDiff) => GETMNLISTD,
    /// MN list diff.
    MnListDiff(MnListDiff) => MNLISTDIFF,
  }

  parsed_empty {
    /// Version acknowledgement.
    Verack => VERACK,
    /// Request peer addresses.
    GetAddr => GETADDR,
    /// Signal addrv2 support.
    SendAddrV2 => SENDADDRV2,
    /// Prefer unsolicited header announcements.
    SendHeaders => SENDHEADERS,
    /// Prefer compressed header announcements.
    SendHeaders2 => SENDHEADERS2,
  }

  stub {
    // Bitcoin base protocol
    /// Block data.
    Block => BLOCK,
    /// BIP152: compact block transactions.
    BlockTxn => BLOCKTXN,
    /// BIP152: compact block.
    CmpctBlock => CMPCTBLOCK,
    /// BIP37: add data to bloom filter.
    FilterAdd => FILTERADD,
    /// BIP37: load bloom filter.
    FilterLoad => FILTERLOAD,
    /// Request block hashes.
    GetBlocks => GETBLOCKS,
    /// BIP152: request compact block transactions.
    GetBlockTxn => GETBLOCKTXN,
    /// BIP37: filtered block.
    MerkleBlock => MERKLEBLOCK,
    /// BIP152: signal compact block support.
    SendCmpct => SENDCMPCT,
    /// Transaction.
    Tx => TX,
    /// BIP330: transaction reconciliation.
    SendTxRcncl => SENDTXRCNCL,
    // Sporks
    /// Spork broadcast/request.
    Spork => SPORK,
    // CoinJoin
    /// CoinJoin: accept denomination.
    Dsa => DSA,
    /// CoinJoin: submit inputs.
    Dsi => DSI,
    /// CoinJoin: final transaction.
    Dsf => DSF,
    /// CoinJoin: sign final transaction.
    Dss => DSS,
    /// CoinJoin: complete.
    Dsc => DSC,
    /// CoinJoin: status update.
    Dssu => DSSU,
    /// CoinJoin: broadcast transaction.
    Dstx => DSTX,
    /// CoinJoin: queue entry.
    Dsq => DSQ,
    /// Sync status count.
    Ssc => SSC,
    // LLMQ / Quorum
    /// LLMQ: final commitment.
    QfCommit => QFCOMMIT,
    /// LLMQ: contribution.
    QContrib => QCONTRIB,
    /// LLMQ: complaint.
    QComplaint => QCOMPLAINT,
    /// LLMQ: justification.
    QJustify => QJUSTIFY,
    /// LLMQ: premature commitment.
    QpCommit => QPCOMMIT,
    /// LLMQ: signing session announcement.
    QSigSesAnn => QSIGSESANN,
    /// LLMQ: signature shares inventory.
    QSigsInv => QSIGSINV,
    /// LLMQ: request signature shares.
    QGetSigs => QGETSIGS,
    /// LLMQ: batched signature shares.
    QbSigs => QBSIGS,
    /// LLMQ: recovered signature.
    QSigRec => QSIGREC,
    /// LLMQ: single signature share.
    QSigShare => QSIGSHARE,
    /// LLMQ: request quorum data.
    QGetData => QGETDATA,
    /// LLMQ: quorum data.
    QData => QDATA,
    // InstantSend / ChainLock
    /// ChainLock signature.
    ClSig => CLSIG,
    /// InstantSend deterministic lock.
    IsdLock => ISDLOCK,
    // Masternode auth / rotation
    /// Masternode authentication.
    MnAuth => MNAUTH,
    /// Request quorum rotation info.
    GetQrInfo => GETQRINFO,
    /// Quorum rotation info.
    QrInfo => QRINFO,
    // Platform
    /// DIP-0031: platform ban.
    PlatformBan => PLATFORMBAN,
  }

  stub_empty {
    /// BIP37: clear bloom filter.
    FilterClear => FILTERCLEAR,
    /// Request mempool contents.
    Mempool => MEMPOOL,
    /// Request active sporks.
    GetSporks => GETSPORKS,
    /// Signal CoinJoin queue relay.
    SendDsq => SENDDSQ,
    /// LLMQ: send recovered signatures.
    QSendRecSigs => QSENDRECSIGS,
    /// LLMQ: watch quorums.
    QWatch => QWATCH,
  }
}
