/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

import init, { parse_block_hex, parse_tx_hex } from "./pkg/demo_parser.js";

/** @type {Record<string, (hex: string) => string>} */
const PARSERS = { block: parse_block_hex, transaction: parse_tx_hex };

/**
 * @param {HTMLElement} label
 * @param {HTMLElement} children
 */
function toggleNode(label, children) {
  const open = children.style.display !== "none";
  children.style.display = open ? "none" : "";
  label.classList.toggle("closed", open);
}

/**
 * @param {string} key
 * @param {unknown} value
 * @returns {HTMLElement}
 */
function buildTree(key, value) {
  if (value !== null && typeof value === "object") {
    const isArr = Array.isArray(value);
    const entries = isArr
      ? value.map((/** @type {unknown} */ v, /** @type {number} */ i) => [String(i), v])
      : Object.entries(/** @type {Record<string, unknown>} */ (value));
    const suffix = isArr ? ` [${value.length}]` : "";

    const node = document.createElement("div");
    node.className = "tree-node";

    const label = document.createElement("span");
    label.className = "tree-label";
    label.textContent = `${key}${suffix}`;
    node.appendChild(label);

    const children = document.createElement("div");
    children.className = "tree-children";
    for (const [k, v] of entries) {
      children.appendChild(buildTree(k, v));
    }
    node.appendChild(children);

    label.addEventListener("click", () => {
      toggleNode(label, children);
    });

    return node;
  }

  const div = document.createElement("div");
  div.className = "leaf";

  const keySpan = document.createElement("span");
  keySpan.className = "key";
  keySpan.textContent = `${key}: `;
  div.appendChild(keySpan);

  const valSpan = document.createElement("span");
  if (value === null) {
    valSpan.className = "val-null";
    valSpan.textContent = "null";
  } else if (typeof value === "boolean") {
    valSpan.className = "val-bool";
    valSpan.textContent = String(value);
  } else if (typeof value === "number") {
    valSpan.className = "val-num";
    valSpan.textContent = String(value);
  } else {
    valSpan.className = "val-str";
    valSpan.textContent = `"${value}"`;
  }
  div.appendChild(valSpan);

  return div;
}

/** @param {string} id @returns {HTMLElement} */
const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

const hexInput = /** @type {HTMLTextAreaElement} */ ($("hex-input"));
const typeSelect = /** @type {HTMLSelectElement} */ ($("type-select"));
const parseBtn = /** @type {HTMLButtonElement} */ ($("parse-btn"));
const clearBtn = /** @type {HTMLButtonElement} */ ($("clear-btn"));
const errorMsg = $("error-msg");
const warnings = $("warnings");
const output = $("output");

/**
 * @param {string[]} msgs
 */
function renderWarnings(msgs) {
  warnings.replaceChildren();
  for (const msg of msgs) {
    const adm = document.createElement("div");
    adm.className = "admonition warning";
    adm.textContent = msg;
    warnings.appendChild(adm);
  }
}

function handleParse() {
  errorMsg.textContent = "";
  warnings.replaceChildren();
  output.replaceChildren();

  const hex = hexInput.value.trim();
  if (!hex) {
    errorMsg.textContent = "Paste hex data above.";
    return;
  }

  const parser = PARSERS[typeSelect.value];
  if (!parser) {
    errorMsg.textContent = `Unknown type: ${typeSelect.value}`;
    return;
  }

  try {
    const result = JSON.parse(parser(hex));
    const data = /** @type {Record<string, unknown>} */ (result.data || result);
    const warns = /** @type {string[]} */ (result.warnings || []);

    if (warns.length > 0) {
      renderWarnings(warns);
    }

    for (const [k, v] of Object.entries(data)) {
      output.appendChild(buildTree(k, v));
    }
  } catch (err) {
    errorMsg.textContent = String(err);
  }
}

function handleClear() {
  hexInput.value = "";
  errorMsg.textContent = "";
  warnings.replaceChildren();
  output.replaceChildren();
}

init()
  .then(() => {
    parseBtn.disabled = false;
    parseBtn.addEventListener("click", handleParse);
    clearBtn.addEventListener("click", handleClear);
  })
  .catch((err) => {
    errorMsg.textContent = `Failed to load WASM module: ${err}`;
  });
