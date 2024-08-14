use risc0_zkvm::guest::env;

fn main() {

    // DUMMY method.
    // It will read and u32 and return 1 if it is less than 100, otherwise 0.
    // read the input
    let input: u32 = env::read();

    // check the input and write the commitment
    if input < 100 {
        env::commit(&1u32);
    } else {
        env::commit(&0u32);
    }

}
