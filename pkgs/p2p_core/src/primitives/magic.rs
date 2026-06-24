//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash network magic bytes.

use dash_primitives::hash_impl;
use dash_types::make_bytes;

make_bytes! {
  /// Four-byte network identifier prepended to every V1 message.
  Magic, 4
}

hash_impl!(Magic);
