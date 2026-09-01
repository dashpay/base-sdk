# Building Docs

The guide is generated using [Zensical](https://pypi.org/project/zensical/) (a fork of
[MkDocs](https://pypi.org/project/mkdocs/)), configured using
[`zensical.toml`](../zensical.toml). Every source file it needs
lives in [`docs/`](..), the rendered site is written to
`docs/.site`.

Most dependencies can be installed using `python -m pip install -e '.[dev]'`.

* Zensical (included in `[dev]`)
* PyMarkdown (included in `[dev]`)
* rjsmin (included in `[dev]`)
* [wasm-pack](https://github.com/wasm-bindgen/wasm-pack)

From the repository root, render the site with

```sh
python docs/build_docs.py build
```

or render it and serve it over localhost with

```sh
python docs/build_docs.py preview
```
