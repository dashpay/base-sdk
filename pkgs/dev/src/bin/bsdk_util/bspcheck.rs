//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Linearized chain verification.

use crate::logging;
use crate::policy;
use crate::Application;

use dash_primitives::Block;
use dash_types::codec::{BaseCodec, DecodeError};

use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::time::Instant;

/// Errors that can occur during chain verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapError {
  /// An I/O error occurred while reading the input stream.
  Io(String),
  /// The input contained no frames at all.
  EmptyInput,
  /// A block's raw bytes could not be decoded into a `Block`.
  Decode { block: u64, error: DecodeError },
  /// Aggregate error after `--no-fastfail` finishes with failures.
  Summary { errors: u64 },
}

impl fmt::Display for BootstrapError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Io(e) => write!(f, "i/o error: {e}"),
      Self::EmptyInput => write!(f, "empty input"),
      Self::Decode { block, error } => write!(f, "block {block}: decode failed: {error}"),
      Self::Summary { errors } => write!(f, "{errors} block(s) failed verification"),
    }
  }
}

impl std::error::Error for BootstrapError {}

impl From<io::Error> for BootstrapError {
  fn from(e: io::Error) -> Self {
    Self::Io(format!("{} ({})", e, e.kind()))
  }
}

mod diskfmt {
  use super::BootstrapError;
  use crate::Application;

  use std::io::{self, Read};

  #[derive(Clone, Debug, Eq, Hash, PartialEq)]
  pub struct FrameHeader {
    pub magic: [u8; 4],
    pub size: u32,
  }

  /// Read an 8-byte linearized chain frame header, return `None` on clean EOF.
  pub fn read_frame_header(reader: &mut impl Read) -> Result<Option<FrameHeader>, BootstrapError> {
    let mut buf = [0u8; 8];
    // Read the first byte to distinguish clean EOF from a truncated header.
    match reader.read_exact(&mut buf[..1]) {
      Ok(()) => {}
      Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
      Err(e) => return Err(BootstrapError::Io(e.to_string())),
    }
    reader
      .read_exact(&mut buf[1..])
      .map_err(|e| BootstrapError::Io(format!("truncated frame header: {e}")))?;
    Ok(Some(FrameHeader {
      magic: [buf[0], buf[1], buf[2], buf[3]],
      size: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    }))
  }

  pub type Chunk = Vec<(u64, Vec<u8>)>;

  /// Read all frames sequentially into memory. Returns `(frames, total_bytes,
  /// reached_eof)`.
  pub fn read_all(reader: &mut impl Read, app: &Application) -> Result<(Chunk, u64, bool), BootstrapError> {
    let mut frames = Vec::new();
    let mut cumulative: u64 = 0;
    let mut index: u64 = 0;

    loop {
      let header = match read_frame_header(reader)? {
        Some(h) => h,
        None => return Ok((frames, cumulative, true)),
      };

      let mut data = vec![0u8; header.size as usize];
      reader.read_exact(&mut data)?;
      cumulative += 8 + header.size as u64;
      frames.push((index, data));

      if (index + 1) % 10000 == 0 {
        crate::logging::log_msg(app, &format!("Read {} blocks from input", index + 1));
      }

      index += 1;
    }
  }
}

fn verify_block(index: u64, data: &[u8]) -> Result<(), BootstrapError> {
  let _block = Block::decode(&mut &data[..]).map_err(|e| BootstrapError::Decode { block: index, error: e })?;
  Ok(())
}

pub fn run(app: &Application, file: &str, no_fastfail: bool) -> Result<(), BootstrapError> {
  let start = Instant::now();
  let from_stdin = file == "-";

  let (input, _file_size): (Box<dyn Read>, Option<u64>) = if from_stdin {
    logging::log_msg(app, "Reading from stdin (streaming)");
    (Box::new(io::stdin().lock()), None)
  } else {
    let full_path = fs::canonicalize(file).unwrap_or_else(|_| file.into());
    let metadata = fs::metadata(file)?;
    let size_mib = metadata.len() / (1024 * 1024);
    logging::log_msg(app, &format!("Reading {} ({size_mib} MiB)", full_path.display()));
    (Box::new(File::open(file)?), Some(metadata.len()))
  };

  let mut reader = BufReader::with_capacity(policy::READ_BUFFER_BYTES, input);

  let first_header = diskfmt::read_frame_header(&mut reader)?.ok_or(BootstrapError::EmptyInput)?;

  logging::log_msg(
    app,
    &format!(
      "First block magic: 0x{:02x}{:02x}{:02x}{:02x}",
      first_header.magic[0], first_header.magic[1], first_header.magic[2], first_header.magic[3],
    ),
  );

  let mut genesis_data = vec![0u8; first_header.size as usize];
  reader.read_exact(&mut genesis_data)?;

  logging::log_msg(app, &format!("Genesis block: {} bytes", genesis_data.len()));

  match verify_block(0, &genesis_data) {
    Ok(()) => {}
    Err(e) => {
      logging::log_msg(app, &format!("Error: {e}"));
      if !no_fastfail {
        return Err(e);
      }
    }
  }

  drop(genesis_data);

  let (chunk, _chunk_bytes, _reached_eof) = diskfmt::read_all(&mut reader, app)?;

  let mut errors: u64 = 0;
  for (idx, data) in &chunk {
    match verify_block(*idx, data) {
      Ok(()) => {}
      Err(e) => {
        logging::log_msg(app, &format!("Error: {e}"));
        errors += 1;
        if !no_fastfail {
          return Err(e);
        }
      }
    }
  }

  let total = chunk.len() as u64 + 1;
  let runtime = logging::format_runtime(start.elapsed());
  logging::log_msg(
    app,
    &format!("Verified: {}/{total} blocks in {runtime}", total - errors),
  );

  if errors > 0 {
    return Err(BootstrapError::Summary { errors });
  }

  logging::log_msg(app, "All blocks passed verification");
  Ok(())
}
