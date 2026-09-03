# Introduction

The Base SDK for Dash is a collection of packages that enable applications to parse, construct and interact with the
Dash blockchain. This is achieved by leveraging the [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin)
ecosystem to provide a framework that builds upon existing, familiar APIs and contract expectations.

To achieve this, state-independent portions of the consensus engine have been split into composable packages that can be
imported as needed.

Some packages depend on other packages to expose their full functionality. Packages are primarily placed in three
buckets (see below). When upgrading downstream packages, it is recommended to version-match with the lowermost bucket
utilised by your packages.

* Foundation packages. These packages provide unopinionated Bitcoin-compatible data manipulation.
* Base packages. These packages implement specific algorithms but without chain-distinguishing consensus logic.
* Protocol packages. These packages define the Dash protocol as deployed, blocks, transactions, chain parameters.

<!-- [include:README.md:crate-graph] -->

*Note: Solid lines are build dependencies, dotted lines are test dependencies.*

## Versioning and Platform Policy

> [!WARNING]
>
> As the Base SDK is in early development, the public contract and API shape should be considered **unstable**. Releases
> are made sporadically on an *ad hoc* basis with `YYYY-MM-DD` [tags](https://github.com/dashpay/base-sdk/tags) and
> packages have a fixed version of `0.0.0`. Stable releases will be made in accordance with
> [Semantic Versioning](https://semver.org/).

* The minimum supported Rust version has an upper cap at the version of Rust available with Debian
  [`stable`](https://wiki.debian.org/DebianStable) (last updated, [`trixie`](https://wiki.debian.org/DebianTrixie)).
  The current MSRV is 1.85.0 ([source](https://github.com/dashpay/base-sdk/blob/2026-04-22/.github/workflows/build_stable.yml#L34-L35)).

* Some features rely on Rust `nightly` (notably affected is `core::simd`, see
  [rust-lang/portable-simd#364](https://github.com/rust-lang/portable-simd/issues/364)), building packages with the
  `full` feature will pull in these dependencies. Consuming packages built on Rust `stable` are recommended to manually
  select the features desired from the package alongside `std`.

  * Packages are validated against the version of nightly pinned in
    [`rust-toolchain.toml`](https://github.com/dashpay/base-sdk/blob/2026-04-22/rust-toolchain.toml), SDK functionality
    is tested only against the pinned version. Regressions on succeeding versions are evaluated on a case-by-case basis.

* `no_std` + `alloc` is the baseline target, the public contract is limited by what is feasible by this baseline target.
  `std` is primarily a passthrough to `std` features provided by dependent crates, no additional functionality is
  offered by the SDK *itself* through `std` enablement.

Crates by default offer the following features, any additional features offered by crates are defined in their
respective sections.

| Feature     | Capabilities enabled                        | Defined by every package          |
| ----------- | ------------------------------------------- | --------------------------------- |
| _(baseline)_ | `no_std` + `alloc`, always available.       | Yes                               |
| `std`       | Standard library support.                   | Yes                               |
| `full`      | All non-conflicting features.               | Yes                               |
| `serde`     | Serialization using `serde`.                | **No** (dependent on feature set) |

## Is the SDK a full node?

The Base SDK is not a full node implementation nor does it intend to be. `no_std` + `alloc` restricts I/O and networking
making it better suited for resource-constrained, sandboxed or otherwise limited environments. The public contract
reflects this, restricted to only stateless or relatively context-independent portions of the overall consensus engine.

For a more batteries-included solution, consider [`rust-dashcore`](https://github.com/dashpay/rust-dashcore) or the C++
reference implementation, [Dash Core](https://github.com/dashpay/dash) over
[RPC](https://docs.dash.org/en/stable/docs/core/api/remote-procedure-calls.html),
[REST](https://docs.dash.org/en/stable/docs/core/api/http-rest.html) or
[ZMQ](https://docs.dash.org/en/stable/docs/core/api/zmq.html).
