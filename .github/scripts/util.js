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
 * @returns {Promise<{ mergeable_state: string, commits: number }>}
 */
async function getPullDetail({ github, owner, repo, prNumber }) {
  let commits = 0;
  for (let i = 0; i < MERGEABLE_RETRIES; i++) {
    const { data: detail } = await github.rest.pulls.get({
      owner,
      repo,
      pull_number: prNumber,
    });
    commits = detail.commits;
    if (detail.mergeable_state !== "unknown") {
      return { mergeable_state: detail.mergeable_state, commits };
    }
    await sleep(MERGEABLE_DELAY_MS);
  }
  return { mergeable_state: "unknown", commits };
}

module.exports = { BASE_BRANCH, getPullDetail, listOpenPulls, sleep };
