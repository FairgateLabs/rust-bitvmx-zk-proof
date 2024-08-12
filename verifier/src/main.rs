use risc0_zkvm::Receipt;
use risc0_zkp::core::digest::Digest;

pub fn deserialize_receipt(name: &str) -> Receipt {

    //deserialize receipt from file using bin code
    let path = std::path::Path::new(name);
    let receipt_bytes = std::fs::read(path).unwrap();
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).unwrap();
    receipt

}
fn main() {
    
    let args: Vec<String> = std::env::args().collect();
    let receipt = deserialize_receipt(args[1].as_str());
    let digest = Digest::new( [4090783106, 2484911864, 2044201760, 1676034390, 2692133236, 1489696604, 393880035, 2754212766] );

    receipt.verify(digest).unwrap();
    println!("Verification succeeded!");

}
