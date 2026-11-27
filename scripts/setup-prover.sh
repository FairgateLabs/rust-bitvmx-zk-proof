#!/bin/sh
# Prepares an Ubuntu 24.04 instance with an NVIDIA T4 GPU (g4dn) as the prover image of the job dispatcher:
# - the NVIDIA driver, the CUDA toolkit and docker,
# - this repository in /home/ubuntu/rust-bitvmx-zk-proof, with `host` (cpu build) and `host-gpu` (cuda build) in
#   target/release,
# - the guest .bin in guests/,
# - the docker image of the groth16 prover.
#
# scripts/build-ami.sh runs it through SSM, as root, in two steps with a reboot between them:
#   setup-prover.sh system
#   setup-prover.sh build <source .tar.gz> <guest .bin> [<test input>]
#
# `system` installs the packages and the NVIDIA driver, which loads after the reboot. `build` unpacks the source,
# builds both binaries, installs the guest and pulls the groth16 prover image. With a test input, it also proves it with
# the guest, as a check of the whole image.

set -eu

USER_NAME=ubuntu
HOME_DIR=/home/$USER_NAME
REPO=$HOME_DIR/rust-bitvmx-zk-proof
CUDA_PACKAGE=cuda-toolkit-12-9

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

as_user() {
    runuser -l "$USER_NAME" -c "$1"
}

system() {
    # Automatic updates would compete with the build for the package lock and restart services in the middle of it,
    # and on the image they would change the provers without notice.
    systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service || true

    apt-get update -q
    apt-get install -yq build-essential pkg-config libssl-dev protobuf-compiler clang libclang-dev cmake git curl \
        unzip ca-certificates gnupg ubuntu-drivers-common

    ubuntu-drivers install

    curl -fsSL https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb \
        -o /tmp/cuda-keyring.deb
    dpkg -i /tmp/cuda-keyring.deb
    apt-get update -q
    apt-get install -yq "$CUDA_PACKAGE"

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc]" \
        "https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        >/etc/apt/sources.list.d/docker.list
    apt-get update -q
    apt-get install -yq docker-ce docker-ce-cli containerd.io
    usermod -aG docker "$USER_NAME"

    # The dispatcher uploads the input of each job to S3 and the job reads it with the AWS CLI.
    curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscli.zip
    rm -rf /tmp/aws && unzip -q /tmp/awscli.zip -d /tmp
    /tmp/aws/install --update

    as_user 'curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal'
}

build() {
    source_tar=$1
    guest_bin=$2
    test_input=${3:-}

    nvidia-smi -L

    rm -rf "$REPO"
    mkdir -p "$REPO"
    tar -xzf "$source_tar" -C "$REPO"
    chown -R "$USER_NAME:$USER_NAME" "$REPO"

    # The cuda kernels are built for the GPU of this machine (-arch=native), so the image only serves the same GPU.
    # The cpu build stays as `host`.
    # shellcheck disable=SC2016
    cuda_env='export PATH=/usr/local/cuda/bin:$HOME/.cargo/bin:$PATH LD_LIBRARY_PATH=/usr/local/cuda/lib64'
    as_user "$cuda_env && cd $REPO && cargo build --release -p host --features risc0-zkvm/cuda"
    as_user "cp $REPO/target/release/host $REPO/target/release/host-gpu"
    as_user "$cuda_env && cd $REPO && cargo build --release -p host"

    as_user "mkdir -p $REPO/guests"
    install -o "$USER_NAME" -g "$USER_NAME" -m 0644 "$guest_bin" "$REPO/guests/$(basename "$guest_bin")"

    # The cpu build makes the groth16 proof with this docker image, whose tag is in the source of risc0-groth16.
    groth16_version=$(awk '/^name = "risc0-groth16"$/ { getline; gsub(/"/, "", $3); print $3 }' "$REPO/Cargo.lock")
    image=$(grep -ho 'risczero/risc0-groth16-prover:[^"]*' \
        "$HOME_DIR"/.cargo/registry/src/*/risc0-groth16-"$groth16_version"/src/prove/docker.rs | head -n 1)
    docker pull -q "$image"

    if [ -n "$test_input" ]; then
        test_proof "$test_input" "$REPO/guests/$(basename "$guest_bin")"
    fi
}

test_proof() {
    out=$(mktemp -d)
    chmod 777 "$out"
    bin=$REPO/target/release
    "$bin/host-gpu" prove-succinct --input "$1" --elf "$2" --output "$out/succinct.bin" --json "$out/succinct.json" \
        --p254-seal "$out/p254.seal"
    "$bin/host" wrap-groth16 --input "$out/succinct.bin" --p254-seal "$out/p254.seal" --json "$out/output.json" \
        --json-input "$out/succinct.json"
    grep -q '"status":"OK"' "$out/output.json" || {
        echo "The test proof failed: $(cat "$out/output.json")" >&2
        exit 1
    }
    echo "The test proof is OK"
    rm -rf "$out"
}

case "${1:-}" in
system) system ;;
build)
    shift
    build "$@"
    ;;
*)
    echo "Usage: $0 system | build <source .tar.gz> <guest .bin> [<test input>]" >&2
    exit 1
    ;;
esac
