/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Rules for dash-pkc.
 */

/**
 * Holds if `name` belongs to `arm` alone for `role`, exempting the other arms
 * from offering it. Rows live in `pkc.model.yml`.
 */
extensible predicate armOnly(string arm, string role, string name);

/**
 * Holds if `arm` cannot carry `trait` at `role`, though the other arms do.
 * Rows live in `pkc.model.yml`.
 */
extensible predicate armLacksTrait(string arm, string role, string trait);
