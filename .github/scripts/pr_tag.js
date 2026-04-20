/*!
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 */

// @ts-check

const STALE_DAYS = 60;
const BASE_BRANCH = "develop";

/** @enum {string} */
const Labels = {
  STALE: "stale",
  NEEDS_REBASE: "needs-rebase",
};

const MERGEABLE_RETRIES = 5;
const MERGEABLE_DELAY_MS = 3000;

/**
 * @param {{ github: import("@actions/github").getOctokit, context: import("@actions/github").context }} params
 */
module.exports = async ({ github, context }) => {
  const { data: pulls } = await github.rest.pulls.list({
    owner: context.repo.owner,
    repo: context.repo.repo,
    state: "open",
    base: BASE_BRANCH,
    per_page: 100,
  });

  const now = new Date();

  for (const pr of pulls) {
    const labels = pr.labels.map((l) => l.name);

    const updated = new Date(pr.updated_at);
    const daysSinceUpdate = Math.floor((now - updated) / (1000 * 60 * 60 * 24));
    const isStale = daysSinceUpdate >= STALE_DAYS;
    const hasStale = labels.includes(Labels.STALE);

    if (isStale && !hasStale) {
      await github.rest.issues.addLabels({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: pr.number,
        labels: [Labels.STALE],
      });
      console.log(`PR #${pr.number}: tagged stale (${daysSinceUpdate} days)`);
    } else if (!isStale && hasStale) {
      await github.rest.issues.removeLabel({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: pr.number,
        name: Labels.STALE,
      });
      console.log(`PR #${pr.number}: removed stale`);
    }

    let mergeableState = "unknown";
    for (let i = 0; i < MERGEABLE_RETRIES; i++) {
      const { data: prDetail } = await github.rest.pulls.get({
        owner: context.repo.owner,
        repo: context.repo.repo,
        pull_number: pr.number,
      });
      if (prDetail.mergeable_state !== "unknown") {
        mergeableState = prDetail.mergeable_state;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, MERGEABLE_DELAY_MS));
    }

    if (mergeableState === "unknown") {
      continue;
    }

    const hasConflicts = mergeableState === "dirty";
    const hasRebaseLabel = labels.includes(Labels.NEEDS_REBASE);

    if (hasConflicts && !hasRebaseLabel) {
      await github.rest.issues.addLabels({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: pr.number,
        labels: [Labels.NEEDS_REBASE],
      });
      console.log(`PR #${pr.number}: tagged needs-rebase`);
    } else if (!hasConflicts && hasRebaseLabel) {
      await github.rest.issues.removeLabel({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: pr.number,
        name: Labels.NEEDS_REBASE,
      });
      console.log(`PR #${pr.number}: removed needs-rebase`);
    }
  }
};
