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

The first proof is a Stark, that is later converted into a Sanrk (groth16). 

RISC0 implemented a circuit to verify any Stark. 


## Steps

### Requirements

Currently RISC0 support for Groth16 is only available on x86/x64.
Also some of the scripts are aimed to run in linux, and Docker is required to be installed.

This steps where tested on WSL (Ubuntu 22) on Windows 11

1. Install rust
1. Install risc zero / binutils / etc

### Setup Phase

This command will build the program in guest, and dump it's unique and secure identifier. 

`cargo run --release --bin host dump-id -o image_id.json`

This command will use the identifier and the expected journal result (in this are the bytes of a 1 in u32 representation)

`cargo run --release --bin verifier generate-claim -i image_id.json --journal 1,0,0,0`


### Proving

The first step is to generate the stark proof, passing the expected input. In this dummy example, any input bellow 100 will output a journal with 1, and zero otherwise.

`cargo run --release --bin host prove-stark --input 50 --output stark-proof.bin`

The second step is to generate the snark proof for the stark proof.

`cargo run --release --bin host prove-snark --input stark-proof.json --output snark-seal.json`

### Verifiying

`cargo run --release --bin verifier generate-claim -i image_id.json --journal 1,0,0,0 --seal snark-seal.json`




**TODO:**
- Generate on setup the gorth16 c verifier
- Split the input


