/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

import init, { scanhash } from "./pkg/demo_solver.js";

// Nonces per scanhash call; yields between batches for progress reporting.
const BATCH_SIZE = 100000;
const ready = init();

self.onmessage = async (e) => {
  const { version, prevHash, time, bits, scriptSig, scriptPubKey, amount, nonceFrom, nonceCount } = e.data;
  let totalHashes = 0;

  try {
    await ready;
    let cur = nonceFrom;
    let remaining = nonceCount;
    while (remaining > 0) {
      const count = Math.min(BATCH_SIZE, remaining);
      const raw = scanhash(version, prevHash, time, bits, scriptSig, scriptPubKey, amount, cur, count);
      const r = JSON.parse(raw);
      totalHashes += r.hashes;

      if (r.found) {
        self.postMessage({ ok: true, result: r, totalHashes });
        return;
      }

      self.postMessage({ progress: true, totalHashes });
      cur = (cur + count) >>> 0;
      remaining -= count;
    }
    self.postMessage({ done: true, totalHashes });
  } catch (err) {
    self.postMessage({ ok: false, error: String(err) });
  }
};
