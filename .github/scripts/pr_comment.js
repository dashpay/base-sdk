/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

const { getMergeableState, listOpenPulls } = require("./util");

const COMMENT_TAG = "<!-- pr-status-bot -->";

/**
 * @param {{ github: import("@actions/github").getOctokit, context: import("@actions/github").context }} params
 */
module.exports = async ({ github, context }) => {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const pulls = await listOpenPulls({ github, owner, repo });
  const fileCache = await buildFileCache({ github, owner, repo, pulls });

  for (const pr of pulls) {
    const body = await buildComment({ github, owner, repo, pr, pulls, fileCache });
    await upsertComment({ github, owner, repo, prNumber: pr.number, body });
    console.log(`PR #${pr.number}: comment updated`);
  }
};

/**
 * @param {{ github: any, owner: string, repo: string, pulls: any[] }} params
 * @returns {Promise<Map<number, string[]>>}
 */
async function buildFileCache({ github, owner, repo, pulls }) {
  const cache = new Map();
  const results = await Promise.all(
    pulls.map((pr) =>
      github.rest.pulls.listFiles({
        owner,
        repo,
        pull_number: pr.number,
        per_page: 100,
      }).then((res) => ({ number: pr.number, files: res.data.map((f) => f.filename) }))
    )
  );
  for (const entry of results) {
    cache.set(entry.number, entry.files);
  }
  return cache;
}

/**
 * @param {{ github: any, owner: string, repo: string, pr: any, pulls: any[], fileCache: Map<number, string[]> }} params
 * @returns {Promise<string>}
 */
async function buildComment({ github, owner, repo, pr, pulls, fileCache }) {
  const mergeableState = await getMergeableState({ github, owner, repo, prNumber: pr.number });
  const isDirty = mergeableState === "dirty";

  const ourFiles = new Set(fileCache.get(pr.number) || []);
  const potentialConflicts = [];

  for (const other of pulls) {
    if (other.number === pr.number) {
      continue;
    }
    const otherFiles = fileCache.get(other.number) || [];
    const overlap = otherFiles.filter((f) => ourFiles.has(f));
    if (overlap.length > 0) {
      potentialConflicts.push({ url: other.html_url });
    }
  }

  let banner;
  if (isDirty) {
    banner = "> [!CAUTION]\n> This pull request conflicts with the base branch. Please rebase and force-push.";
  } else if (potentialConflicts.length > 0) {
    banner =
      "> [!WARNING]\n> This pull request may have conflicts, please coordinate with the authors of these pull requests.";
  } else {
    banner = "> [!NOTE]\n> This pull request has no conflicts! 🎊 🎉 🎊";
  }

  let conflictSection = "";
  if (potentialConflicts.length > 0) {
    conflictSection = "## Potential conflicts\n\n";
    for (const c of potentialConflicts) {
      conflictSection += `* ${c.url}\n`;
    }
    conflictSection += "\n";
  }

  return `${COMMENT_TAG}\n${banner}\n\n${conflictSection}`;
}

/**
 * @param {{ github: any, owner: string, repo: string, prNumber: number, body: string }} params
 */
async function upsertComment({ github, owner, repo, prNumber, body }) {
  const { data: comments } = await github.rest.issues.listComments({
    owner,
    repo,
    issue_number: prNumber,
    per_page: 100,
  });

  const existing = comments.find((c) => c.body.startsWith(COMMENT_TAG));

  if (existing) {
    await github.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body,
    });
  } else {
    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body,
    });
  }
}
