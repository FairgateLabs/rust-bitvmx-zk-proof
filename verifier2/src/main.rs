use risc0_groth16::{ProofJson, PublicInputsJson, Verifier, VerifyingKeyJson};
use risc0_groth16::{fr_from_hex_string, split_digest, Seal, VerifyingKey};
use risc0_zkvm::{Receipt, VerifierContext};
use risc0_zkp::core::digest::Digest;
use risc0_zkp::verify::VerificationError;
use risc0_zkp::core::hash::sha::Sha256;
use risc0_zkvm::sha;//::Impl;
use risc0_zkvm::sha::Digestible;
use hex;
use std::io::Read;

pub fn deserialize_receipt(name: &str) -> Receipt {

    //deserialize receipt from file using bin code
    let path = std::path::Path::new(name);
    let receipt_bytes = std::fs::read(path).unwrap();
    let receipt: Receipt = bincode::deserialize(&receipt_bytes).unwrap();
    receipt

}

fn main() -> Result<(), VerificationError> {
    let args: Vec<String> = std::env::args().collect();
    let receipt = deserialize_receipt(args[1].as_str());
    let digest = Digest::new( [4090783106, 2484911864, 2044201760, 1676034390, 2692133236, 1489696604, 393880035, 2754212766] );

    //receipt.inner.groth16().unwrap().verifier_parameters

    let seal = &receipt.inner.groth16().unwrap().seal;
    let claim = &receipt.inner.groth16().unwrap().claim;
    let result = claim.digest();
    println!("{}", hex::encode(seal));
    println!("{}", hex::encode(result.as_bytes()));



    let ctx = VerifierContext::default();
    let params = ctx
            .groth16_verifier_parameters
            .as_ref()
            .ok_or(VerificationError::VerifierParametersMissing)?;

    println!("control root: {:?}", params.control_root);
    println!(": {:?}", params.verifying_key);

    let (a0, a1) =
        split_digest(params.control_root).map_err(|_| VerificationError::ReceiptFormatError)?;
    
    println!("a0: {:?}", a0);
    println!("a1: {:?}", a1);

    let (c0, c1) = split_digest(claim.digest())
        .map_err(|_| VerificationError::ReceiptFormatError)?;

    println!("c0: {:?}", c0);
    println!("c1: {:?}", c1);

    let mut id_bn554: Digest = params.bn254_control_id;
    id_bn554.as_mut_bytes().reverse();
    let id_bn254_fr = fr_from_hex_string(&hex::encode(id_bn554))
        .map_err(|_| VerificationError::ReceiptFormatError)?;

    println!("id_bn254_fr: {:?}", id_bn254_fr);

    Verifier::new(
        &Seal::from_vec(&seal).map_err(|_| VerificationError::ReceiptFormatError)?,
        &[a0, a1, c0, c1, id_bn254_fr],
        &params.verifying_key,
    )
    .map_err(|_| VerificationError::ReceiptFormatError)?
    .verify()
    .map_err(|_| VerificationError::InvalidProof)?;

    Ok(())

}
