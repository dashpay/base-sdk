<!-- pyml disable-num-lines 3 no-bare-urls -->
`base-sdk` uses a family of tools and scripts to maintain correctness and code quality. These scripts are written in
Python 3.x and thus, assume a host capable of running Python. For guidance on installing Python on your host, visit
https://www.python.org/downloads/

<!-- [start:setup] -->

## Preparing the virtual environment

To avoid conflicting with your existing environment or with Python-based native packages managed by your host, it is
recommended to create a fresh virtual environment.

> [!NOTE]
> This guide presumes [`uv`](https://github.com/astral-sh/uv) has already been installed on your host. Please refer to
> your program of choice's documentation if using a different manager.

```bash
# Create .venv and install the versions uv.lock pins
uv sync --locked --extra dev

# Enter venv
source .venv/bin/activate
```

> [!WARNING]
> The minimum supported version is Python 3.11, support for prior versions are not expected. If you are running a more
> recent version of Python and are experiencing problems, please
> [file an issue](https://github.com/dashpay/base-sdk/issues/new).

## Installing dependencies

[`pyproject.toml`](../pyproject.toml) supplies most but not all dependencies needed to run the lint suite, the following
packages need to be additionally sourced.

* [Git](https://git-scm.com/install/)
* [CodeQL 2.24 or higher](https://github.com/github/codeql-cli-binaries/releases) (Rust support was added in 2.23.3,
  [source](https://github.blog/changelog/2025-10-23-codeql-2-23-3-adds-a-new-rust-query-rust-support-and-easier-c-c-scanning/))
* [Node.js 24 or higher](https://nodejs.org/en/download) (current LTS,
  [source](https://nodejs.org/en/blog/release/v24.11.0))

### macOS (with [Homebrew](https://brew.sh/))

> [!NOTE]
> Versioned formulae like `node@24` are considered "keg-only", which may require additional steps in order to be
> discoverable in `PATH`, see guidance from Homebrew
> ([source](https://docs.brew.sh/FAQ#what-does-keg-only-mean)).

```bash
brew install codeql git node@24
```

### Linux/WSL

See manual installation steps for CodeQL from GitHub
([source](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli)),
you may need to update your shell to add your installation path to `PATH` so that `codeql` can be discovered by the
lint script.

Neither CodeQL nor taplo are available in official Debian or Fedora repositories and must be sourced per vendor
guidance.

#### Installing `taplo`

> [!WARNING]
> `.[dev]` doesn't provide `taplo`, needed to run `lint_cargo` on Arm64 Linux. This is due to a release limitation at
> PyPi ([source](https://pypi.org/project/taplo/0.9.3/#files)). The following guidance is not necessary on AMD64 Linux
> or macOS.

An alternative to procuring releases from the maintainers ([source](https://github.com/tamasfe/taplo/releases)) is to
install it as a Rust binary crate.

```bash
cargo install taplo-cli
```

#### Debian

```bash
# Required because Debian trixie ships Node 20.x, deprecated in April 2026
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt install git nodejs -y
```

#### Fedora

```bash
sudo dnf install -y git nodejs24
```

<!-- [end:setup] -->

<!-- [start:bisect] -->

## Verifying bisectability

As a general rule of thumb, each commit must individually compile and pass linters. To help with this, we have a helper
script, [`git_filter.py`](./git_filter.py) that creates a temporary worktree and executes supplied commands for each
commit in a specified range so the worktree isn't blocked by the validation run.

```bash
# Replace 'branch_name' with the name of your branch
./contrib/git_filter.py --fast-fail develop branch_name -- bash -c 'cargo clippy --all-targets --no-default-features -- -D warnings &&
cargo clippy --all-targets --features full -- -D warnings &&
cargo test --all-targets --features full &&
./maint/lint_all.py'
```

<!-- [end:bisect] -->
