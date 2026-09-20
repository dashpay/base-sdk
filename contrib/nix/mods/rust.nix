# Rust toolchains, default included in PATH, remaining as TOOLCHAIN_*

{
  default,
  lib,
  toolchains,
}:

let
  # A path per non-default toolchain, since only one can own `cargo` at a time.
  named = lib.mapAttrs' (name: t: lib.nameValuePair "TOOLCHAIN_${lib.toUpper name}" "${t}") (
    lib.filterAttrs (name: _: name != default) toolchains
  );

  # rust-overlay symlinks a toolchain together, leaving the standard library
  # source under a sysroot the CodeQL Rust extractor cannot resolve, costing
  # us prelude resolution. Hand it the component those links land in.
  rustSrc = toolchains.${default}.availableComponents.rust-src;
in
{
  packages = [ toolchains.${default} ];

  env = {
    CARGO_TERM_COLOR = "always";
    CODEQL_EXTRACTOR_RUST_OPTION_SYSROOT_SRC = "${rustSrc}/lib/rustlib/src/rust/library";
  }
  // named;
}
