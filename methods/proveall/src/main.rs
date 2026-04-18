use risc0_zkvm::guest::env;

//This is a dummy ZKP that will prove anything
//any input will be made a commitment and returned in the journal
fn main() {
    let input: Vec<u8> = env::read();
    // Pack 4 bytes per u32 word instead of 1 byte per u32
    let mut padded = input;
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    let words: Vec<u32> = padded
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    env::commit_slice(&words);
}
