# Build BitVMX ZK-Proof

This project is allows to generate a Zero Knowledge Proof to be used with BitVMX.
For this we have some tools that allows to split the three phases of a ZKP.
1. Setup
1. Proving
1. Verification

## The Program to Verify

This repo contains a dummy example of a ZKP using RISC0.
The proof is inside [methods/guest/src](methods/guest/src)

Inside [host/src](host/src) is the enviornment that allows to get the information required for the setup, execute the proof and verifiy it.

The first proof is a Stark, that is later converted into a Snark (groth16). 


## Steps

### Requirements

Currently RISC0 support for Groth16 is only available on x86/x64.
Also some of the scripts are aimed to run in linux, and Docker is required to be installed.

This steps where tested on WSL (Ubuntu 20.04) on Windows 11 and also in Azure Standard E4as v4

To make docker to be accesible from wsl follow this [instructions](https://docs.docker.com/desktop/wsl/)

#### Clone repo
`clone git@github.com:FairgateLabs/rust-bitvmx-zk-proof.git`

#### Install docker
`sudo snap install docker`

#### Install rust
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
Option: (1) standard installation

`bash` (or logout/login to update paths)

#### build tools
`sudo apt-get update`

`sudo apt -y install build-essential`

`sudo apt -y install pkg-config libssl-dev`


#### install risczero
`curl -L https://risczero.com/install | bash`

`source ~/.bashrc` (to update path)

~~`rzup --version 1.0.5`~~

`cargo install cargo-binstall`

`cargo binstall cargo-risczero --version 1.0.5`

`cargo risczero install`

### Setup Phase

This command will build the program in guest, and dump it's unique and secure identifier. 

`cargo run --release --bin host -- dump-id -o image_id.json`

This command will use the identifier and the expected journal result (in this are the bytes of a 1 in u32 representation)

`cargo run --release --bin verifier -- generate-claim -i image_id.json --journal 1,0,0,0`

### Template Setup

If the proof will be inserted in the constants.h directly:
`cargo run --release --bin verifier -- template-setup --image-id image_id.json --template ..\bitvmx-zk-verifier\templates\constants_template.h -o intermediate.h`

If the proof will be provided as input to the program:
`cargo run --release --bin verifier -- template-setup --image-id image_id.json --template ..\bitvmx-zk-verifier\templates\constants_template.h -o constants.h --zero-proof`

### Proving

The first step is to generate the stark proof, passing the expected input. In this dummy example, any input bellow 100 will output a journal with 1, and zero otherwise.

`cargo run --release --bin host -- prove-stark --input 50 --output stark-proof.bin`

The second step is to generate the snark proof for the stark proof.

Check running `docker` works fine. In that case run this command:
`cargo run --release --bin host -- prove-snark --input stark-proof.bin --output snark-seal.json`

If not, try runnign it in this way:
`sudo RISC0_WORK_DIR=./ RUST_LOG=debug ./target/release/host prove-snark --input stark-proof.bin --output snark-seal.json`

### Verifiying

`cargo run --release --bin verifier -- verify -i image_id.json --journal 1,0,0,0 --seal snark-seal.json`

### Template Proof 

`cargo run --release --bin verifier -- template-proof --journal 1,0,0,0 --seal snark-seal.json -t intermediate.h -o constants.h`

### Proof to Input Hex 
`cargo run --release --bin verifier -- proof-as-input --journal 1,0,0,0 --seal snark-seal.json`


