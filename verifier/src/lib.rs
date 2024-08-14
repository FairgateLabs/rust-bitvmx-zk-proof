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

// Function to safely return a clone of the private field
fn get_verifying_key_clone(params: &Groth16ReceiptVerifierParameters) -> ark_groth16::VerifyingKey<Bn254> {
    unsafe {
        let priv_verifying: *const ark_groth16::VerifyingKey<Bn254> = &params.verifying_key as *const _ as *const ark_groth16::VerifyingKey<Bn254>;
        (*priv_verifying).clone()
    }
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

    let vk = get_verifying_key_clone(&params);
    template = template.replace("vk_alpha_g1",  &bytes_to_str(&g1_to_c_bytes(g1_strings_to_vec(split_g1(format!("{:?}",vk.alpha_g1))))));
    template = template.replace("vk_beta_g2",   &bytes_to_str(&g2_to_c_bytes(g2_strings_to_vec(split_g2(format!("{:?}",vk.beta_g2))))));
    template = template.replace("vk_gamma_g2",  &bytes_to_str(&g2_to_c_bytes(g2_strings_to_vec(split_g2(format!("{:?}",vk.gamma_g2))))));
    template = template.replace("vk_delta_g2",  &bytes_to_str(&g2_to_c_bytes(g2_strings_to_vec(split_g2(format!("{:?}",vk.delta_g2))))));
    template = template.replace("vk_gamma_abc_0",  &bytes_to_str(&g1_to_c_bytes(g1_strings_to_vec(split_g1(format!("{:?}",vk.gamma_abc_g1[0]))))));
    template = template.replace("vk_gamma_abc_1",  &bytes_to_str(&g1_to_c_bytes(g1_strings_to_vec(split_g1(format!("{:?}",vk.gamma_abc_g1[1]))))));
    template = template.replace("vk_gamma_abc_2",  &bytes_to_str(&g1_to_c_bytes(g1_strings_to_vec(split_g1(format!("{:?}",vk.gamma_abc_g1[2]))))));
    template = template.replace("vk_gamma_abc_3",  &bytes_to_str(&g1_to_c_bytes(g1_strings_to_vec(split_g1(format!("{:?}",vk.gamma_abc_g1[3]))))));
    template = template.replace("vk_gamma_abc_4",  &bytes_to_str(&g1_to_c_bytes(g1_strings_to_vec(split_g1(format!("{:?}",vk.gamma_abc_g1[4]))))));

    //only variable part, the rest could be hardcoded
    //interesting to keep it in this way as claim generation could change over time (risc0 versioning)
    template = template.replace("claim_pre", &bytes_to_str(&claim_pre.as_bytes()));


    write(output_fname, template).unwrap();

}


