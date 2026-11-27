#!/bin/sh
# Builds a RISC Zero guest in docker, so the same source gives the same .bin and image id on any machine, and writes
# the .bin that `host` takes with `--elf`.
#
# Usage: scripts/build-guest.sh <guest Cargo.toml> <root> <output .bin>
#
# <root> is the directory that docker copies to build the guest: it has to contain the guest and every path
# dependency of it, usually the root of the repository of the guest.
#
# Example, for the check fork guest of union-bridge-client:
#   scripts/build-guest.sh ../union-bridge-client/crates/check-fork/zkp/guest/Cargo.toml ../union-bridge-client \
#       guests/check-fork-guest.bin
#
# Needs docker and cargo. It prints the image id, in the format of `host dump-id`.

set -eu

if [ $# -ne 3 ]; then
    echo "Usage: $0 <guest Cargo.toml> <root> <output .bin>" >&2
    exit 1
fi

MANIFEST=$(realpath "$1")
ROOT=$(realpath "$2")
OUTPUT=$3
mkdir -p "$(dirname "$OUTPUT")"
OUTPUT=$(realpath "$(dirname "$OUTPUT")")/$(basename "$OUTPUT")

cd "$(dirname "$0")/.."

# risc0-build reads the version of the local RISC Zero rust toolchain (`rzup install rust`) to choose a rustc flag, even
# when it builds in docker. Without that toolchain, a temporary RISC0_HOME names a version: any version after 1.81 gives
# the flag that the docker image needs.
if ! ls "${RISC0_HOME:-$HOME/.risc0}"/toolchains/*rust* >/dev/null 2>&1; then
    RISC0_HOME=$(mktemp -d)
    export RISC0_HOME
    trap 'rm -rf "$RISC0_HOME"' EXIT
    mkdir -p "$RISC0_HOME/toolchains/v1.97.0-rust-$(rustc -vV | sed -n 's/^host: //p')"
    printf '[default_versions]\nrust = "1.97.0"\n' >"$RISC0_HOME/settings.toml"
fi

cargo run --release --quiet -p guest-builder -- --manifest "$MANIFEST" --root "$ROOT" --output "$OUTPUT"
