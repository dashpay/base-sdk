The programs here write the BLS corpora in `pkgs/pkc/corpus` from a reference implementation release. Every
value comes from the release's BLS library (dashbls, with relic) or from the release's own sources: its BLS wrapper,
serialization and hashing, and commitment hash function. The other values are fixed inputs written in the programs.

| Corpus | Program |
| --- | --- |
| `bls_aggregate.json5` | `gen_aggregate.cpp` |
| `bls_hash.json5` | `gen_hash.cpp` |
| `bls_ies.json5` | `gen_ies.cpp` |
| `bls_keygen.json5` | `gen_keygen.cpp` |
| `bls_llmq_100.json5` | `gen_llmq_100.cpp` |
| `bls_read.json5` | `gen_read.cpp` |
| `bls_secure_aggregate.json5` | `gen_secure_aggregate.cpp` |
| `bls_serialize.json5` | `gen_serialize.cpp` |
| `bls_sign.json5` | `gen_sign.cpp` |
| `bls_threshold.json5` | `gen_threshold.cpp` |

Each program prints its corpus on stdout. For `bls_llmq_100.json5`, its `member_pks` and `member_sig` values are fixed
inputs, which the program checks against the commitment hash it computes. For `bls_hash.json5`, the program repeats the
legacy map's hashing and reduction steps with relic, which the library does not expose, and the library's own point
anchors them.

`bls_read.json5` records how the release's BLS library reads public keys and signatures from bytes under each scheme.
Its inputs come from seeded classes that `gen_read.cpp` builds with relic's field and curve operations. Each outcome is
the library's read, with an all-zero input marked null as the release's key and signature types do. An input is valid
when the library reads an element other than the identity that encodes back to it, and invalid otherwise. For an input
the legacy scheme reads as valid, relic also gives whether its `x` has a point on the curve.

`bls_dh.json5` is not covered by these programs yet; it will be covered with the IES work.

* `common.hpp` holds the hex and corpus layout helpers shared by every program.
* `core.hpp` holds the helpers for the programs that use the release's own sources.
* `no_random.cpp` stands in for the release's random source, which no program uses.
* `build.sh` builds a release's BLS library from its `src/dashbls` and links the programs against it.
* `regen.sh` builds two releases, runs every program against both and writes the corpora.

## Regenerating

`build.sh` needs a checkout of [the reference implementation](https://github.com/dashpay/dash), autotools, a C++20
compiler and GMP. It builds only the release's `src/dashbls`, with the library options the release's configure passes
(`--disable-shared --with-pic`) and tests and benchmarks off. Error checking in relic is off by default, as in a release
build. The programs link with the GMP paths that configure found, such as Homebrew's on macOS, plus any `CPPFLAGS`,
`CXXFLAGS` and `LDFLAGS` in the environment. `build.sh` keeps the library build in its output directory and compiles the
programs again on every run. After a failed library build, remove the output directory before running it again.

```bash
pkgs/pkc/contrib/regen.sh ~/dash /tmp/bls-corpus pkgs/pkc/corpus
```

`regen.sh` builds v24.0.0-rc.5 (8163290aa0307ed4bc2fc0ba15b78c20d61dfa88) and v23.1.8
(728f5055836c6d29806412fc7223ac8fe05af991), and `build.sh` stops if a tag resolves to another commit. `regen.sh` writes
nothing unless both releases write the same bytes for every corpus. To run one program against one release:

```bash
pkgs/pkc/contrib/build.sh ~/dash v24.0.0-rc.5 8163290aa0307ed4bc2fc0ba15b78c20d61dfa88 /tmp/bls-v24
/tmp/bls-v24/bin/gen_keygen >pkgs/pkc/corpus/bls_keygen.json5
```
