
use risc0_groth16::Seal;
use risc0_zkvm::{MaybePruned, Receipt, ReceiptClaim};
use risc0_zkp::core::digest::Digest;
use std::io::Read;
use ark_bn254::{G1Affine, G2Affine};
use ark_serialize::CanonicalDeserialize;

use num_bigint::BigInt;
use std::str::FromStr;


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


pub fn bytes_to_str(bytes: &[u8]) -> String {
    bytes.iter().map(|s| s.to_string()).collect::<Vec<String>>().join(", ")
}


// Convert the U256 value to a byte array in big-endian format
pub fn from_u256_bigint(value: &str) -> Vec<u8> {
    //to_fixed_array(hex::decode(value).unwrap()).to_vec()
    to_fixed_array(
    BigInt::from_str(value)
                .unwrap()
                .to_bytes_be()
                .1).to_vec()
}

pub fn to_fixed_array(input: Vec<u8>) -> [u8; 32] {
    let mut fixed_array = [0u8; 32];
    let start = core::cmp::max(32, input.len()) - core::cmp::min(32, input.len());
    fixed_array[start..].copy_from_slice(&input[input.len().saturating_sub(32)..]);
    fixed_array
}


pub fn get_image_id(image_id: &String) -> [u32; 8] {
    let mut file = std::fs::File::open(image_id).unwrap();
    let mut image_id_json = String::new();
    file.read_to_string(&mut image_id_json).unwrap();
    let value = json::parse(&image_id_json).unwrap();
    //map the vector inside values to [u32,8]
    let mut image_id: [u32; 8] = [0; 8];
    for (i, v) in value.members().enumerate() {
        image_id[i] = v.as_u32().unwrap();
    }
    image_id
}


pub fn get_claim(image_id: &String, journal: &Vec<u8> ) -> ReceiptClaim{
    
    let image_id = get_image_id(image_id);
    let digest = Digest::new(image_id);

    let journal_maybe = MaybePruned::Value(journal.clone());
    let claim = ReceiptClaim::ok(digest, journal_maybe);
    claim

}

pub fn get_seal(proof: &str) -> Seal {
    let mut file = std::fs::File::open(proof).unwrap();
    let mut proof_json = String::new();
    file.read_to_string(&mut proof_json).unwrap();
    let values = json::parse(&proof_json).unwrap();
    let seal_vec = values.members().map(|x| x.as_u8()).collect::<Option<Vec<u8>>>().unwrap();
    Seal::from_vec(&seal_vec).unwrap()
}

pub fn g1_to_c_bytes(mut g1: Vec<Vec<u8>>) -> Vec<u8> {
    if g1[1][31] % 2 == 1 {
        g1[0][0] += 128;
    }
    g1[0].reverse();
    g1[0].clone()
}

pub fn g2_to_c_bytes(g2: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
    let mut g2_x = g2[0].clone();
    if g2[1][1][31] % 2 == 1 {
        g2_x[0][0] += 128;
    }
    g2_x[0].reverse();
    g2_x[1].reverse();

    let mut bytes_g2 = g2_x[1].clone();
    bytes_g2.extend(g2_x[0].iter());
    bytes_g2
}

pub fn split_g1(data: String) -> Vec<String> {
    let parts: Vec<&str> = data
        .trim_matches(|c| c == '(' || c == ')')
        .split(',')
        .collect();

    let first_part = parts[0].trim();
    let second_part = parts[1].trim();
    vec![first_part.to_string(), second_part.to_string()]
}

pub fn g1_strings_to_vec(data: Vec<String>) -> Vec<Vec<u8>> {
   vec![from_u256_bigint(&data[0]), from_u256_bigint(&data[1])]
}

pub fn g2_strings_to_vec(data: Vec<String>) -> Vec<Vec<Vec<u8>>> {
   vec![vec![from_u256_bigint(&data[0]), from_u256_bigint(&data[1])],
        vec![from_u256_bigint(&data[2]), from_u256_bigint(&data[3])]]
}

pub fn split_g2(data: String) -> Vec<String> {
// Trim the parentheses around the whole string
    let trimmed_input = data.trim_matches(|c| c == '(' || c == ')');
    
    // Split by comma
    let parts: Vec<&str> = trimmed_input.split("), QuadExtField(").collect();

    let mut results = Vec::new();

    for part in parts {
        // Remove the "QuadExtField(" prefix and the closing ")" if it's present
        let cleaned = part.trim_start_matches("QuadExtField(").trim_end_matches(')');
        
        // Split by the `+` sign
        let sub_parts: Vec<&str> = cleaned.split(" + ").collect();
        
        // Remove the `* u` from the second part and trim any whitespace
        let first_value = sub_parts[0].trim();
        let second_value = sub_parts[1].trim().trim_end_matches(" * u");

        // Add the results to the vector
        results.push(second_value.to_string());
        results.push(first_value.to_string());
    }

    results
}



// Deserialize an element over the G1 group from bytes in big-endian format
pub(crate) fn g1_from_bytes(elem: &[Vec<u8>]) -> G1Affine {
    let g1_affine: Vec<u8> = elem[0]
        .iter()
        .rev()
        .chain(elem[1].iter().rev())
        .cloned()
        .collect();

    G1Affine::deserialize_uncompressed(&*g1_affine).unwrap()
}


// Deserialize an element over the G2 group from bytes in big-endian format
pub(crate) fn g2_from_bytes(elem: &[Vec<Vec<u8>>]) -> G2Affine {
    let g2_affine: Vec<u8> = elem[0][1]
        .iter()
        .rev()
        .chain(elem[0][0].iter().rev())
        .chain(elem[1][1].iter().rev())
        .chain(elem[1][0].iter().rev())
        .cloned()
        .collect();

    G2Affine::deserialize_uncompressed(&*g2_affine).unwrap()
}
