//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Entrypoint for Base SDK Debug Utility.

mod logging;

use std::env;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::process::ExitCode;
use std::sync::Mutex;

/// Application shared state.
pub struct Application {
  /// Optional log-file writer.
  pub log: Mutex<Option<BufWriter<File>>>,
  /// Path to the log file on disk.
  pub log_path: String,
}

impl fmt::Debug for Application {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Application")
      .field("log_path", &self.log_path)
      .finish_non_exhaustive()
  }
}

impl Application {
  fn new(log_path: Option<String>) -> Self {
    let log_path = log_path.unwrap_or_default();
    let log = if log_path.is_empty() {
      Mutex::new(None)
    } else {
      match OpenOptions::new().write(true).create_new(true).open(&log_path) {
        Ok(f) => Mutex::new(Some(BufWriter::new(f))),
        Err(e) => {
          eprintln!("warning: could not create log file: {e}");
          Mutex::new(None)
        }
      }
    };
    Self { log, log_path }
  }
}

fn main() -> ExitCode {
  let app = Application::new(None);
  logging::print_banner(&app);

  let args: Vec<String> = env::args().skip(1).collect();
  let joined_args = args.join(" ");
  logging::log_msg(
    &app,
    &format!(
      "Running on {} {} ({}) with args \"{joined_args}\"",
      env::consts::OS,
      env::consts::FAMILY,
      env::consts::ARCH,
    ),
  );

  if let Some(mut w) = app.log.lock().ok().and_then(|mut g| g.take()) {
    if let Err(e) = w.flush() {
      eprintln!("fatal: log flush failed: {e}");
      return ExitCode::FAILURE;
    }
    logging::log_msg(&app, &format!("Log saved to {}", app.log_path));
  }

  ExitCode::SUCCESS
}
