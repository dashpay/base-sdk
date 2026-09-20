# CodeQL CLI

{ pkgs, unstable }:

let
  version = "2.27.0";

  # Fetching more recent CodeQL releases requires `unstable` and `x86_64-darwin`
  # as a target is no longer supported since 26.11 (see nixos/nixpkgs#535508),
  # though GitHub themselves still provide binaries that support Intel Macs so
  # we rely on a pin for `x86_64-darwin` and consume from `unstable` otherwise.
  pinned = pkgs.codeql.overrideAttrs (_: {
    inherit version;

    src = pkgs.fetchzip {
      url = "https://github.com/github/codeql-cli-binaries/releases/download/v${version}/codeql.zip";
      hash = "sha256-8WhsburnhVWvVLTNOmAwmkjwN45exmKmw7Q5elTjYiI=";
    };
  });

  codeql = if pkgs.stdenv.hostPlatform.system == "x86_64-darwin" then pinned else unstable.codeql;
in
{
  packages = [ codeql ];
}
