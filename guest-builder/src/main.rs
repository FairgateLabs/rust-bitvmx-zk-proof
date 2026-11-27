//! Builds a RISC Zero guest in the docker image of risc0-build, so the same source gives the same binary and image
//! id on any machine, and writes the guest `.bin` that `host` takes with `--elf`: the guest ELF packed with the zkVM
//! kernel.

use std::path::PathBuf;

use clap::Parser;
use risc0_binfmt::{compute_image_id, ProgramBinary};
use risc0_build::{
    docker_build, BuildStatus, DockerOptionsBuilder, GuestOptionsBuilder, TARGET_DIR,
};

#[derive(Parser)]
#[command(about = "Build a RISC Zero guest in docker and write its .bin and image id")]
struct Args {
    /// Cargo.toml of the guest crate
    #[arg(long, value_name = "FILE")]
    manifest: PathBuf,

    /// Directory that docker copies to build the guest. It has to contain the guest and every path dependency of it.
    #[arg(long, value_name = "DIR")]
    root: PathBuf,

    /// Where to write the guest .bin
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

fn package_name(manifest: &PathBuf) -> Result<String, String> {
    let text = std::fs::read_to_string(manifest)
        .map_err(|e| format!("Failed to read {}: {}", manifest.display(), e))?;
    let value: toml::Value = toml::from_str(&text)
        .map_err(|e| format!("Failed to parse {}: {}", manifest.display(), e))?;
    value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("{} has no package name", manifest.display()))
}

fn run(args: Args) -> Result<(), String> {
    let root = args
        .root
        .canonicalize()
        .map_err(|e| format!("Failed to find {}: {}", args.root.display(), e))?;
    let name = package_name(&args.manifest)?;

    let docker = DockerOptionsBuilder::default()
        .root_dir(root.clone())
        .build()
        .map_err(|e| e.to_string())?;
    let opts = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .map_err(|e| e.to_string())?;
    match docker_build(&args.manifest, &opts)
        .map_err(|e| format!("The docker build failed: {}", e))?
    {
        BuildStatus::Success => {}
        BuildStatus::Skipped => {
            return Err("The build was skipped because RISC0_SKIP_BUILD is set".to_string())
        }
    }

    // docker_build writes the release directory of the guest under <root>/TARGET_DIR/<package>/<target>/docker.
    let elf_path = root
        .join(TARGET_DIR)
        .join(name.replace('-', "_"))
        .join("riscv32im-risc0-zkvm-elf")
        .join("docker")
        .join(&name);
    let elf = std::fs::read(&elf_path)
        .map_err(|e| format!("Failed to read {}: {}", elf_path.display(), e))?;

    let binary = ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let image_id =
        compute_image_id(&binary).map_err(|e| format!("Failed to compute the image id: {}", e))?;
    std::fs::write(&args.output, &binary)
        .map_err(|e| format!("Failed to write {}: {}", args.output.display(), e))?;

    // Same format as `host dump-id`.
    println!("image_id={}", hex::encode(image_id.as_bytes()));
    println!("bin={}", args.output.display());
    Ok(())
}

fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
