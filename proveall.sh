#cargo build --release 
#cargo build --release --manifest-path ../BitVMX-CPU/Cargo.toml --bin emulator
mkdir output
echo Dumping ELF ID
target/release/host dump-id --elf target/riscv-guest/methods/proveall/riscv32im-risc0-zkvm-elf/release/proveall.bin --output output/proveall-id.hex
echo Generating stark proof
target/release/host prove-stark --input input.hex --elf target/riscv-guest/methods/proveall/riscv32im-risc0-zkvm-elf/release/proveall.bin --output output/prove-all-stark.bin --json output/prove-all.json
echo Converting into snark
target/release/host prove-snark --input output/prove-all-stark.bin --json output/prove-all.json 
echo Converting into input for the emulator
target/release/verifier proof-as-input --image-id output/proveall-id.hex --proof output/prove-all.json >output/proof-as-input.hex
echo Running emulator with proof as input
../BitVMX-CPU/target/release/emulator execute --elf ../rust-bitvmx-client/verifiers/generic-verifier.elf --no-hash --input $(cat output/proof-as-input.hex)