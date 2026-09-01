/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

import init, { merkle_root } from "./pkg/demo_solver.js";

const RE_HEX = /^[0-9a-fA-F]+$/;
const RE_DIGITS = /^[0-9]+$/;

// Coinbase scriptSig embedded in the Dash genesis block.
const SCRIPT_SIG =
  "04ffff001d01044c5957697265642030392f4a616e2f3230313420546865" +
  "204772616e64204578706572696d656e7420476f6573204c6976653a204f" +
  "76657273746f636b2e636f6d204973204e6f7720416363657074696e6720" +
  "426974636f696e73";

// Pay-to-pubkey output script used in the genesis coinbase.
const SCRIPT_PUBKEY =
  "41040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4" +
  "d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070" +
  "ac7b03a9ac";

// Known genesis block header fields per network.
const PRESETS = {
  mainnet: {
    time: 1390095618,
    bits: 0x1e0ffff0,
    nonce: 28917698,
    hash: "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
  },
  testnet: {
    time: 1390666206,
    bits: 0x1e0ffff0,
    nonce: 3861367235,
    hash: "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
  },
};

// Default coinbase reward in duffs (50 DASH).
const AMOUNT_DUFFS = "5000000000";
// Genesis block has no parent.
const PREV_HASH = "0".repeat(64);
// Full u32 nonce space (2^32).
const NONCE_MAX = 0x100000000;
// Time to wait for a closer nonce from a higher-priority thread before accepting.
const GRACE_TIMEOUT_MS = 30 * 1000;
// 1 DASH = 100,000,000 duffs.
const DUFFS_PER_DASH = 1e8;
// Minimum worker threads; divisor applied to navigator.hardwareConcurrency.
const MIN_THREADS = 2;
const THREAD_DIVISOR = 4;

/** @param {string} id @returns {HTMLElement} */
const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

const networkSel = /** @type {HTMLSelectElement} */ ($("gen-network"));
const amountInput = /** @type {HTMLInputElement} */ ($("gen-amount"));
const amountToggle = /** @type {HTMLButtonElement} */ ($("gen-amount-toggle"));
const sigInput = /** @type {HTMLTextAreaElement} */ ($("gen-scriptsig"));
const sigToggle = /** @type {HTMLButtonElement} */ ($("gen-sig-toggle"));
const pkInput = /** @type {HTMLTextAreaElement} */ ($("gen-scriptpubkey"));
const timeInput = /** @type {HTMLInputElement} */ ($("gen-time"));
const bitsInput = /** @type {HTMLInputElement} */ ($("gen-bits"));
const bitsToggle = /** @type {HTMLButtonElement} */ ($("gen-bits-toggle"));
const versionInput = /** @type {HTMLInputElement} */ ($("gen-version"));
const nonceInput = /** @type {HTMLInputElement} */ ($("gen-nonce"));
const merkleOutput = /** @type {HTMLInputElement} */ ($("gen-merkle"));
const hashOutput = /** @type {HTMLInputElement} */ ($("gen-hash"));
const solveBtn = /** @type {HTMLButtonElement} */ ($("gen-solve"));
const resetBtn = /** @type {HTMLButtonElement} */ ($("gen-reset"));
const solveInfo = $("gen-solve-info");
const matchNote = $("gen-match-note");
const coinbaseError = $("gen-coinbase-error");
const headerError = $("gen-header-error");
const versionWarn = $("gen-version-warn");

/** @type {"hex"|"ascii"} */
let sigMode = "hex";
/** @type {"hex"|"dec"} */
let bitsMode = "hex";
/** @type {"dash"|"duffs"} */
let amountMode = "duffs";
/** @type {Worker[]} */
let workers = [];
let graceTimer = 0;
let wasmReady = false;

function currentPreset() {
  return PRESETS[/** @type {keyof PRESETS} */ (networkSel.value)];
}

/** @param {number} khs */
function fmtRate(khs) {
  if (khs >= 1000) {
    return `${(khs / 1000).toFixed(1)} Mh/s`;
  }
  return `${khs.toFixed(1)} Kh/s`;
}

function stopSolving() {
  for (const w of workers) {
    w.terminate();
  }
  workers = [];
  clearTimeout(graceTimer);
  graceTimer = 0;
  solveBtn.disabled = false;
  solveBtn.textContent = "Solve";
  nonceInput.readOnly = false;
}

function loadPreset() {
  stopSolving();
  const p = currentPreset();
  amountMode = "duffs";
  amountToggle.textContent = "duffs";
  amountInput.value = AMOUNT_DUFFS;
  sigMode = "hex";
  sigToggle.textContent = "hex";
  sigInput.value = SCRIPT_SIG;
  pkInput.value = SCRIPT_PUBKEY;
  timeInput.value = String(p.time);
  bitsMode = "hex";
  bitsToggle.textContent = "hex";
  bitsInput.value = `0x${p.bits.toString(16).padStart(8, "0")}`;
  versionInput.value = "1";
  nonceInput.value = String(p.nonce);
  hashOutput.value = "";
  solveInfo.textContent = "";
  matchNote.classList.add("hidden");
  coinbaseError.textContent = "";
  coinbaseError.classList.add("hidden");
  headerError.textContent = "";
  headerError.classList.add("hidden");
  checkVersion();
  updateMerkleRoot();
}

/** @param {HTMLElement} el @param {string} msg */
function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove("hidden");
}

function checkVersion() {
  const v = parseInt(versionInput.value, 10);
  versionWarn.classList.toggle("hidden", v === 1 || isNaN(v));
}

/** @param {string} hex @returns {boolean} */
function isValidHex(hex) {
  return hex.length > 0 && hex.length % 2 === 0 && RE_HEX.test(hex);
}

/** @param {string} v @returns {boolean} */
function isU32(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n <= 0xFFFFFFFF;
}

/** @param {string} v @returns {boolean} */
function isI32(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= -0x80000000 && n <= 0x7FFFFFFF;
}

function updateMerkleRoot() {
  if (!wasmReady) {
    return;
  }
  const sig = getScriptSigHex();
  const pk = pkInput.value.trim();
  const amount = getAmountDuffs();
  if (!isValidHex(sig) || !isValidHex(pk)) {
    merkleOutput.value = "";
    return;
  }
  try {
    merkleOutput.value = merkle_root(sig, pk, amount);
  } catch {
    merkleOutput.value = "";
  }
}

function validate() {
  coinbaseError.textContent = "";
  coinbaseError.classList.add("hidden");
  headerError.textContent = "";
  headerError.classList.add("hidden");
  if (!isValidHex(getScriptSigHex())) {
    showError(coinbaseError, "Signature script: invalid hex (must be even-length hex characters)");
    return false;
  }
  if (!isValidHex(pkInput.value.trim())) {
    showError(coinbaseError, "Output script: invalid hex (must be even-length hex characters)");
    return false;
  }
  const amount = getAmountDuffs();
  if (!/^\d+$/.test(amount)) {
    showError(coinbaseError, "Amount: invalid value");
    return false;
  }
  if (!isU32(String(parseBits())) || parseBits() === 0) {
    showError(headerError, "Difficulty: invalid value");
    return false;
  }
  if (!isU32(timeInput.value.trim())) {
    showError(headerError, "Timestamp: invalid value");
    return false;
  }
  if (!isI32(versionInput.value.trim())) {
    showError(headerError, "Version: invalid value");
    return false;
  }
  if (!isU32(nonceInput.value.trim())) {
    showError(headerError, "Nonce: invalid value");
    return false;
  }
  return true;
}

/** @returns {string} */
function getScriptSigHex() {
  if (sigMode === "hex") {
    return sigInput.value.trim();
  }
  const encoder = new TextEncoder();
  const bytes = encoder.encode(sigInput.value);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** @returns {number} */
function parseBits() {
  let v = bitsInput.value.trim();
  if (bitsMode === "hex") {
    if (v.startsWith("0x") || v.startsWith("0X")) {
      v = v.slice(2);
    }
    return RE_HEX.test(v) ? parseInt(v, 16) : NaN;
  }
  return RE_DIGITS.test(v) ? parseInt(v, 10) : NaN;
}

/** @returns {string} */
function getAmountDuffs() {
  const v = amountInput.value.trim();
  if (amountMode === "duffs") {
    return v;
  }
  return String(Math.round(parseFloat(v) * DUFFS_PER_DASH));
}

function toggleAmount() {
  const duffs = getAmountDuffs();
  if (amountMode === "duffs") {
    amountMode = "dash";
    amountToggle.textContent = "DASH";
    amountInput.value = (Number(duffs) / DUFFS_PER_DASH).toFixed(8);
  } else {
    amountMode = "duffs";
    amountToggle.textContent = "duffs";
    amountInput.value = duffs;
  }
}

function toggleSig() {
  if (sigMode === "hex") {
    const hex = sigInput.value.trim();
    if (!isValidHex(hex)) {
      return;
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    const decoder = new TextDecoder("utf-8", { fatal: false });
    sigInput.value = decoder.decode(bytes);
    sigMode = "ascii";
    sigToggle.textContent = "ASCII";
  } else {
    const hex = getScriptSigHex();
    sigInput.value = hex;
    sigMode = "hex";
    sigToggle.textContent = "hex";
  }
}

function toggleBits() {
  const bits = parseBits();
  if (isNaN(bits)) {
    return;
  }
  if (bitsMode === "hex") {
    bitsMode = "dec";
    bitsToggle.textContent = "dec";
    bitsInput.value = String(bits);
  } else {
    bitsMode = "hex";
    bitsToggle.textContent = "hex";
    bitsInput.value = `0x${bits.toString(16).padStart(8, "0")}`;
  }
}

function startSolve() {
  if (!validate()) {
    return;
  }
  stopSolving();
  hashOutput.value = "";
  solveInfo.textContent = "";
  matchNote.classList.add("hidden");
  coinbaseError.textContent = "";
  coinbaseError.classList.add("hidden");
  headerError.textContent = "";
  headerError.classList.add("hidden");

  const nonce = parseInt(nonceInput.value, 10);
  const payload = {
    version: parseInt(versionInput.value, 10),
    prevHash: PREV_HASH,
    time: parseInt(timeInput.value, 10),
    bits: parseBits(),
    scriptSig: getScriptSigHex(),
    scriptPubKey: pkInput.value.trim(),
    amount: getAmountDuffs(),
  };

  solveBtn.disabled = true;
  solveBtn.textContent = "Solving...";
  nonceInput.readOnly = true;

  const t0 = performance.now();
  const threadCount = Math.max(MIN_THREADS, ((navigator.hardwareConcurrency || THREAD_DIVISOR) / THREAD_DIVISOR) | 0);
  solveInfo.textContent = `Scanning nonces (${threadCount} threads)...`;
  launchParallelScan(payload, nonce >>> 0, threadCount, t0);
}

/**
 * @param {object} payload
 * @param {number} nonceStart
 * @param {number} threadCount
 * @param {number} t0
 */
function launchParallelScan(payload, nonceStart, threadCount, t0) {
  const chunkSize = Math.floor(NONCE_MAX / threadCount);
  const remainder = NONCE_MAX - chunkSize * threadCount;
  /** @type {number[]} */
  const perWorkerHashes = new Array(threadCount).fill(0);
  /** @type {boolean[]} */
  const threadDone = new Array(threadCount).fill(false);
  /** @type {{idx: number, result: object}|null} */
  let bestResult = null;
  let solved = false;

  function acceptBest() {
    if (solved || !bestResult) {
      return;
    }
    clearTimeout(graceTimer);
    solved = true;
    const total = perWorkerHashes.reduce((a, b) => a + b, 0);
    onSolved(/** @type {any} */ (bestResult.result), total, t0);
  }

  function tryFinalize() {
    if (solved || !bestResult) {
      return;
    }
    for (let j = 0; j < bestResult.idx; j++) {
      if (!threadDone[j]) {
        return;
      }
    }
    acceptBest();
  }

  let offset = 0;
  for (let i = 0; i < threadCount; i++) {
    const from = (nonceStart + offset) >>> 0;
    const count = chunkSize + (i < remainder ? 1 : 0);
    offset += count;

    const w = new Worker(new URL("worker.js", import.meta.url), { type: "module" });
    workers.push(w);

    const idx = i;
    w.onmessage = (e) => {
      if (solved) {
        return;
      }
      const msg = e.data;

      if (msg.progress) {
        perWorkerHashes[idx] = msg.totalHashes;
        const total = perWorkerHashes.reduce((a, b) => a + b, 0);
        const secs = (performance.now() - t0) / 1000;
        const rate = secs > 0 ? ` at ${fmtRate(total / secs / 1000)}` : "";
        solveInfo.textContent = `${(total / 1e6).toFixed(1)}M hashes${rate}...`;
        return;
      }

      if (msg.ok) {
        perWorkerHashes[idx] = msg.totalHashes;
        threadDone[idx] = true;
        if (!bestResult || idx < bestResult.idx) {
          bestResult = { idx, result: msg.result };
          clearTimeout(graceTimer);
          if (idx > 0) {
            graceTimer = setTimeout(acceptBest, GRACE_TIMEOUT_MS);
          }
        }
        tryFinalize();
        return;
      }

      if (msg.done) {
        perWorkerHashes[idx] = msg.totalHashes;
        threadDone[idx] = true;
        tryFinalize();
        if (!solved && threadDone.every(Boolean) && !bestResult) {
          showError(headerError, "Nonce space exhausted");
          stopSolving();
        }
        return;
      }

      if (msg.error) {
        solved = true;
        showError(headerError, msg.error);
        stopSolving();
      }
    };

    w.onerror = (e) => {
      if (solved) {
        return;
      }
      solved = true;
      showError(headerError, `Worker error: ${e.message}`);
      stopSolving();
    };

    w.postMessage({ ...payload, nonceFrom: from, nonceCount: count });
  }
}

/**
 * @param {{nonce: number, hash: string, merkle_root: string}} result
 * @param {number} totalHashes
 * @param {number} t0
 */
function onSolved(result, totalHashes, t0) {
  const { nonce: solvedNonce, hash, merkle_root: mr } = result;
  const secs = (performance.now() - t0) / 1000;

  nonceInput.value = String(solvedNonce);
  merkleOutput.value = mr;
  hashOutput.value = hash;

  if (totalHashes === 1) {
    solveInfo.textContent = "Solved";
  } else {
    const rate = secs > 0 ? ` at ${fmtRate(totalHashes / secs / 1000)}` : "";
    solveInfo.textContent = `Solved in ${secs.toFixed(1)}s (${(totalHashes / 1e6).toFixed(1)}M hashes${rate})`;
  }

  const preset = currentPreset();
  if (hash === preset.hash) {
    matchNote.classList.remove("hidden");
  }

  stopSolving();
}

function onCoinbaseChange() {
  hashOutput.value = "";
  solveInfo.textContent = "";
  matchNote.classList.add("hidden");
  updateMerkleRoot();
}

networkSel.addEventListener("change", loadPreset);
resetBtn.addEventListener("click", loadPreset);
amountToggle.addEventListener("click", toggleAmount);
amountInput.addEventListener("input", onCoinbaseChange);
sigToggle.addEventListener("click", toggleSig);
sigInput.addEventListener("input", onCoinbaseChange);
pkInput.addEventListener("input", onCoinbaseChange);
bitsToggle.addEventListener("click", toggleBits);
versionInput.addEventListener("input", checkVersion);
solveBtn.addEventListener("click", startSolve);

init()
  .then(() => {
    wasmReady = true;
    loadPreset();
  })
  .catch((err) => {
    showError(headerError, `Failed to load WASM module: ${err}`);
  });
