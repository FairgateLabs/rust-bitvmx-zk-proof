pub mod format;
pub mod cli;

use risc0_groth16::Verifier;
use risc0_groth16::{fr_from_hex_string, split_digest, Seal};
use risc0_zkvm::{Groth16ReceiptVerifierParameters, VerifierContext};
use risc0_zkvm::sha::Digestible;
use risc0_zkp::core::digest::Digest;
use risc0_zkp::verify::VerificationError;
use hex;
use sha2::{Sha256, Digest as sha2digest};
use std::fs::{read_to_string, write};
use ark_bn254::Bn254;


use crate::format::*;



pub fn generate_proof_bytes_from_seal(seal: Seal) {

    let bytes_proof_a = g1_to_c_bytes(seal.a.clone());
    let bytes_proof_b = g2_to_c_bytes(seal.b.clone());
    let bytes_proof_c = g1_to_c_bytes(seal.c.clone());

    println!("Proof A: {:?}", bytes_proof_a);
    println!("Proof B: {:?}", bytes_proof_b);
    println!("Proof C: {:?}", bytes_proof_c);

}

fn show_claim(image_id: &String, journal: &Vec<u8>) {
    let claim = get_claim(image_id, journal);
    println!("Claim: {:?}", claim);
}

fn get_default_parameters() -> Result<Groth16ReceiptVerifierParameters, VerificationError> {

    let ctx = VerifierContext::default();
    let params = ctx
            .groth16_verifier_parameters
            .as_ref()
            .ok_or(VerificationError::VerifierParametersMissing)?;
    Ok(params.clone())
}

fn verify(image_id: &String, journal: &Vec<u8>, seal_fname: &String) -> Result<(), VerificationError> {
    let claim = get_claim(image_id, journal);
    let seal = get_seal(&seal_fname);

    let result = claim.digest();
    println!("{}", hex::encode(result.as_bytes()));

    let params = get_default_parameters()?;

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
        &seal,
        &[a0, a1, c0, c1, id_bn254_fr],
        &params.verifying_key,
    )
    .map_err(|_| VerificationError::ReceiptFormatError)?
    .verify()
    .map_err(|_| VerificationError::InvalidProof)?;

    println!("Verification successful");

    Ok(())
}


macro_rules! sha256_hash {
    ($($data:expr),+) => {{
        let mut hasher = Sha256::new();
        $(
            hasher.update($data);
        )+
        let result: [u8; 32] = hasher.finalize().try_into().expect("SHA256 should produce a 32-byte output");
        result
    }};
}

pub fn template_setup(image_id_fname: &String, template_fname: &String, output_fname: &String) {

    let mut template = read_to_string(template_fname).unwrap(); 

    let image_id = get_image_id(image_id_fname);
    let claim_pre = Digest::new(image_id);

    let params = get_default_parameters().unwrap();
    let root_id = params.control_root;
    let (a0, a1) = split_digest_custom(root_id); 

    template = template.replace("public_input_0", &bytes_to_str(&a0.to_le_bytes()));
    template = template.replace("public_input_1", &bytes_to_str(&a1.to_le_bytes()));

    template = template.replace("receipt_claim_tag", &bytes_to_str(&sha256_hash!("risc0.ReceiptClaim".as_bytes())));
    template = template.replace("output_tag", &bytes_to_str(&sha256_hash!("risc0.Output".as_bytes())));
    template = template.replace("claim_input", &bytes_to_str(&[0u8; 32]));
    template = template.replace("zeroes", &bytes_to_str(&[0u8; 32]));
    template = template.replace("two_u16", &bytes_to_str(&2u16.to_le_bytes()));
    template = template.replace("four_u16", &bytes_to_str(&4u16.to_le_bytes()));
    template = template.replace("zero_u32", &bytes_to_str(&0u32.to_le_bytes()));

    //only variable part, the rest could be hardcoded
    //interesting to keep it in this way as claim generation could change over time (risc0 versioning)
    template = template.replace("claim_pre", &bytes_to_str(&claim_pre.as_bytes()));

    //println!("{:?}", params.verifying_key.0.alpha_g1);
    unsafe {
        let priv_verifying: *const ark_groth16::VerifyingKey<Bn254> = &params.verifying_key as *const _ as *const ark_groth16::VerifyingKey<Bn254>;
        //println!("{:?}", (*priv_verifying).alpha_g1);
        //println!("{:?}", (*priv_verifying).alpha_g1);
        //let data = format!("{:?}", (*priv_verifying).alpha_g1); 
        let (a,b) = split_g1(format!("{:?}",  (*priv_verifying).alpha_g1));
        println!("{} {}", a,b);
        let alpha_g1_vec = g1_strings_to_vec(&a, &b); 
        println!("{:?}", alpha_g1_vec);
        let g1 = g1_from_bytes(&alpha_g1_vec); //.unwrap();
        let (a,b) = split_g1(format!("{:?}",  g1));
        println!("{} {}", a,b);
        println!("{:?}", g1_to_c_bytes(alpha_g1_vec.clone()));

        println!("========================");

        println!("{:?}", (*priv_verifying).beta_g2);
        let ret = split_g2(format!("{:?}",  (*priv_verifying).beta_g2));
        let g2_vec = g2_strings_to_vec(&ret[0], &ret[1], &ret[2], &ret[3]);
        println!("{:?}", g2_vec);
        let g2 = g2_from_bytes(&g2_vec); //.unwrap();
        println!("{:?}", g2);

        println!("{:?}", g2_to_c_bytes(g2_vec.clone()));


        //let a = vec![from_u256(&proof.pi_a[0])?, from_u256(&proof.pi_a[1])?];
    }

    write(output_fname, template).unwrap();

}


