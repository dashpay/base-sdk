# Changelog

All notable changes to [`dash-num`](https://crates.io/crates/dash-num) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `HashBlob`, `make_hash!` types and `Arith256` serialize as their little-endian storage bytes for machine-readable
  formats, JSON retains hex encoded big-endian string encoding.

### Removed

- `ParseHexError` has moved to `dash-types` as `dash_types::ParseHexError`.
- The `dash_types::Numeric` re-export in favour of a wholesale crate re-export. `dash_num::Numeric` imports must switch
  to `dash_num::__deps::dash_types::Numeric` or depend on `dash-types` directly.

## [0.1.0-beta] - 2026-09-14

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-num-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-num-0.1.0-beta
