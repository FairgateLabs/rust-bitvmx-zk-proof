use risc0_zkvm::guest::env;

//This is a dummy ZKP that will prove anything
//any input will be made a commitment and returned in the journal
fn main() {
    let input: Vec<u8> = env::read();
    env::commit(&input);
}
