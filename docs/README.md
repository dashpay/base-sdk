## Coding Standards

See [`guide_rust.md`](./guide_rust.md) for guidance for new and existing contributors applicable to Rust crates
in the codebase (e.g. [`pkgs/`](../pkgs/)).

## User Guide

The user guide is generated using [Zensical](https://pypi.org/project/zensical/) (a fork of
[MkDocs](https://pypi.org/project/mkdocs/)), configured using [`zensical.toml`](../zensical.toml) with the documentation
located in [`docs/zen`](./zen).

### Dependencies

Most dependencies can be installed using `python -m pip install -e '.[dev]'`.

* Zensical (included in `[dev]`)
* PyMarkdown (included in `[dev]`)
* [wasm-pack](https://github.com/wasm-bindgen/wasm-pack)

### Preview

```sh
python contrib/build_docs.py preview
```

### Building

From repository root

```sh
python contrib/build_docs.py build
```
