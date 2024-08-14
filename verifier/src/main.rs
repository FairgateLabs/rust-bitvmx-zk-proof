//use risc0_groth16::{ProofJson, PublicInputsJson, Verifier, VerifyingKeyJson};
use risc0_groth16::Verifier;
use risc0_groth16::{fr_from_hex_string, split_digest, Seal};//, VerifyingKey};
use risc0_zkvm::{MaybePruned, Receipt, ReceiptClaim, VerifierContext};
use risc0_zkp::core::digest::Digest;
use risc0_zkp::verify::VerificationError;
//use risc0_zkp::core::hash::sha::Sha256;
//use risc0_zkvm::sha;//::Impl;
use risc0_zkvm::sha::Digestible;
use hex;
use std::io::Read;

use clap::{Parser, Subcommand};


pub fn deserialize_receipt(name: &str) -> Receipt {

    //deserialize receipt from file using bin code
    let path = std::path::Path::new(name);
    let receipt_bytes = std::fs::read(path).unwrap();
    bincode::deserialize(&receipt_bytes).unwrap()

}

pub fn split_digest_custom(d: Digest) -> (u128, u128) {
    let big_endian: Vec<u8> = d.as_bytes().to_vec().iter().rev().cloned().collect();
    let middle = big_endian.len() / 2;
    let (b, a) = big_endian.split_at(middle);
    (
        u128::from_be_bytes(a.try_into().unwrap()),
        u128::from_be_bytes(b.try_into().unwrap()),
    )
}


#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {

    /// Generate the claim to be verified
    GenerateClaim {

        /// File name with the dumped image id
        #[arg(short, long, value_name = "FILE", required=true)]
        image_id: String,

        /// Expected journal produces by the stark
        #[arg(short, long, value_delimiter=',', num_args = 1.., required=true)]
        journal: Vec<u8>,
    },

    /// Verify the claim
    Verify {
        /// File name with the dumped image id
        #[arg(short, long, value_name = "FILE", required=true)]
        image_id: String,

        /// Expected journal produces by the stark
        #[arg(short, long, value_delimiter=',', num_args = 1.., required=true)]
        journal: Vec<u8>,

        /// Groth16 proof file
        #[arg(short, long, value_name = "FILE", required=true)]
        seal: String,
    },

}

pub fn get_claim(image_id: &String, journal: &Vec<u8> ) -> ReceiptClaim{
    let mut file = std::fs::File::open(image_id).unwrap();
    let mut image_id_json = String::new();
    file.read_to_string(&mut image_id_json).unwrap();
    let value = json::parse(&image_id_json).unwrap();
    //map the vector inside values to [u32,8]
    let mut image_id: [u32; 8] = [0; 8];
    for (i, v) in value.members().enumerate() {
        image_id[i] = v.as_u32().unwrap();
    }
    let digest = Digest::new(image_id);

    let journal_maybe = MaybePruned::Value(journal.clone());
    let claim = ReceiptClaim::ok(digest, journal_maybe);
    claim

}

pub fn get_seal(proof: &str) -> Vec<u8> {
    let mut file = std::fs::File::open(proof).unwrap();
    let mut proof_json = String::new();
    file.read_to_string(&mut proof_json).unwrap();
    let values = json::parse(&proof_json).unwrap();
    values.members().map(|x| x.as_u8()).collect::<Option<Vec<u8>>>().unwrap()
}

fn main() -> Result<(), VerificationError> {
    
    let cli = Cli::parse();

    let claim;
    let sealed;
    match &cli.command {
        Some(Commands::GenerateClaim { image_id, journal }) => {
            let claim = get_claim(image_id, journal);
            println!("Claim: {:?}", claim);
            return Ok(());

        },
        Some(Commands::Verify { image_id, journal, seal} ) => {
            claim = Some(get_claim(image_id, journal));
            sealed = get_seal(seal);
        },
        None => {
            println!("No command provided");
            return Ok(());
        }

    }



    //let receipt = deserialize_receipt(fname.unwrap());

    //let seal = &receipt.inner.groth16().unwrap().seal;
    let claim = claim.unwrap();
    let result = claim.digest();
    println!("{}", hex::encode(&sealed));
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

    let (a00, a11) = split_digest_custom(params.control_root);
    println!("a00: {:?}", a00);
    println!("a11: {:?}", a11);

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
        &Seal::from_vec(&sealed).map_err(|_| VerificationError::ReceiptFormatError)?,
        &[a0, a1, c0, c1, id_bn254_fr],
        &params.verifying_key,
    )
    .map_err(|_| VerificationError::ReceiptFormatError)?
    .verify()
    .map_err(|_| VerificationError::InvalidProof)?;

    Ok(())

}
