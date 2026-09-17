#cargo build --release 
#cargo build --release --manifest-path ../BitVMX-CPU/Cargo.toml --bin emulator

INPUT_CHECKFORK_ARGS=../../union-bridge-client/crates/check-fork/tester-artifacts/check_fork_args.bin
BIN_CHECKFORK=../../union-bridge-client/target/riscv-guest/check-fork-zkp/check-fork-guest/riscv32im-risc0-zkvm-elf/release/check-fork-guest.bin

mkdir output

echo Dumping ELF ID
target/release/host dump-id --elf $BIN_CHECKFORK --output output/checkfork-id.hex
echo Generating stark proof
target/release/host prove-stark --input $INPUT_CHECKFORK_ARGS --elf $BIN_CHECKFORK --output output/prove-checkfork-stark.bin --json output/prove-checkfork-stark.json
echo Converting into snark
target/release/host prove-snark --input output/prove-checkfork-stark.bin --json output/prove-checkfork-snark.json 
echo Converting into input for the emulator
# prepares inputs for the Emulator (Emulator verifies the groth16 snark proof)
target/release/verifier proof-as-input --image-id output/checkfork-id.hex --proof output/prove-checkfork-snark.json > output/prove-checkfork-input.hex

echo Running emulator with proof as input
../BitVMX-CPU/target/release/emulator execute --elf ../rust-bitvmx-client/verifiers/generic-verifier.elf --no-hash --input $(cat output/prove-checkfork-input.hex)

# # echo Dumping ELF ID
# target/release/host dump-id --elf $BIN_CHECK_COUNTER_FORK --output output/checkcounterfork-id.hex
# echo Generating stark proof
# target/release/host prove-stark --input $INPUT_CHECK_COUNTER_FORK --elf $BIN_CHECK_COUNTER_FORK --output output/prove-checkcounterfork-stark.bin --json output/prove-checkcounterfork-stark.json
# echo Converting into snark
# target/release/host prove-snark --input output/prove-checkcounterfork-stark.bin --json output/prove-checkcounterfork-snark.json
# echo Converting into input for the emulator

# # prepares inputs for the Emulator (Emulator verifies the groth16 snark proof)
# target/release/verifier proof-as-input --image-id output/checkcounterfork-id.hex --proof output/prove-checkcounterfork-snark.json > output/prove-checkcounterfork-input.hex

# echo Running emulator with proof as input
# ../BitVMX-CPU/target/release/emulator execute --elf ../rust-bitvmx-client/verifiers/union-verifier.elf --no-hash --input $(cat output/prove-checkfork-input.hex output/prove-checkcounterfork-input.hex)


