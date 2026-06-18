## Coding Standards

See [`guide_rust.md`](./guide_rust.md) for guidance for new and existing contributors applicable to Rust crates
in the codebase (e.g. [`pkgs/`](../pkgs/)).

## User Guide

The user guide is generated using [Zensical](https://pypi.org/project/zensical/) (a fork of
[MkDocs](https://pypi.org/project/mkdocs/)), configured using [`zensical.toml`](../zensical.toml) with the documentation
located in [`docs/zen`](./zen).

### Building

From repository root

```sh
# Install dependencies
python -m pip install -e '.[dev]'

# Build documentation
python -m zensical build -f zensical.toml
```
