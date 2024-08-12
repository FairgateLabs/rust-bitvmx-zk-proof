use risc0_zkvm::guest::env;

fn main() {
    // TODO: Implement your guest code here

    // read the input
    let input: u32 = env::read();

    if input < 100 {
        env::commit(&1u32);
    } else {
        env::commit(&0u32);
    }

    // TODO: do something with the input

    // write public output to the journal
    //env::commit(&input);
}
