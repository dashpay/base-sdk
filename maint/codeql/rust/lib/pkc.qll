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
 *
 * The rows name what an arm lacks rather than what the arms share, so a
 * method added to one arm and forgotten in another is reported with no list
 * to maintain.
 */
extensible predicate armOnly(string arm, string role, string name);
