/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

const BASE_BRANCH = "develop";
const MERGEABLE_RETRIES = 5;
const MERGEABLE_DELAY_MS = 3000;

/**
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * @param {{ github: any, owner: string, repo: string }} params
 * @returns {Promise<any[]>}
 */
async function listOpenPulls({ github, owner, repo }) {
  const { data: pulls } = await github.rest.pulls.list({
    owner,
    repo,
    state: "open",
    base: BASE_BRANCH,
    per_page: 100,
  });
  return pulls;
}

/**
 * @param {{ github: any, owner: string, repo: string, prNumber: number }} params
 * @returns {Promise<string>}
 */
async function getMergeableState({ github, owner, repo, prNumber }) {
  for (let i = 0; i < MERGEABLE_RETRIES; i++) {
    const { data: detail } = await github.rest.pulls.get({
      owner,
      repo,
      pull_number: prNumber,
    });
    if (detail.mergeable_state !== "unknown") {
      return detail.mergeable_state;
    }
    await sleep(MERGEABLE_DELAY_MS);
  }
  return "unknown";
}

module.exports = { BASE_BRANCH, getMergeableState, listOpenPulls, sleep };
