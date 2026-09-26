# Changelog

All notable changes to [`dash-pkc`](https://crates.io/crates/dash-pkc) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The following types serialize as raw bytes for machine-readable formats, following changes to `dash-types` and
  `dash-num`. JSON and other human-readable formats are unaffected by this change.

  `BlsPkBytes`, `BlsSigBytes`, `BlsPkHash`, `BlsShareId`, `BlsIes{Blob,Multi}Bytes`, `BlsPublicKey`, `BlsSignature`,
  `Bls{Pk,Sig}Share`, `BlsIes{Blob,Multi}`, `EcdsaPkBytes`, `EcdsaSigBytes`, `EcdsaRecSigBytes`, `EcdsaPkHash`,
  `EcdsaPublicKey`, `EcdsaSignature`, `EcdsaRecSignature`, `EddsaPkBytes`, `EddsaSigBytes`, `EddsaPkHash`,
  `EddsaPublicKey`, `EddsaSignature`.

## [0.1.0-beta] - 2026-09-15

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-pkc-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-pkc-0.1.0-beta
