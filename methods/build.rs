use std::collections::HashMap;
use std::path::PathBuf;

use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};

const RISC0_DOCKER_IMAGE: &str =
    "r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3";

fn main() {
    let skip_build = std::env::var("RISC0_SKIP_BUILD").is_ok_and(|value| !value.is_empty());
    if skip_build {
        println!(
            "cargo:warning=RISC0_SKIP_BUILD is set: guest programs will not be rebuilt. \
             Generated ELF constants will be empty and image IDs will be zero. \
             Existing guest binaries on disk are left unchanged."
        );
    }

    if let Ok(tag) = std::env::var("RISC0_DOCKER_CONTAINER_TAG") {
        assert_eq!(
            tag, RISC0_DOCKER_IMAGE,
            "RISC0_DOCKER_CONTAINER_TAG must match the project's pinned RISC Zero builder"
        );
    }

    // The tag documents the toolchain version; the digest makes the linux/amd64 image immutable.
    // RISC Zero's Docker builder uses each guest Cargo.lock with --locked.
    let docker_options = DockerOptionsBuilder::default()
        .root_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."))
        .docker_container_tag(RISC0_DOCKER_IMAGE)
        .build()
        .expect("RISC Zero Docker options should be valid");
    let guest_options = GuestOptionsBuilder::default()
        .use_docker(docker_options)
        .build()
        .expect("RISC Zero guest options should be valid");

    risc0_build::embed_methods_with_options(HashMap::from([
        ("bitvmx", guest_options.clone()),
        ("proveall", guest_options),
    ]));
}
