use bincode;
use hex;
use serde;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;

pub fn serialize_image_id(image_id: [u32; 8]) -> String {
    image_id
        .iter()
        .map(|id| format!("{:08x}", id))
        .collect::<Vec<String>>()
        .join("")
}

pub fn deserialize_image_id(hex_str: &str) -> Result<[u32; 8], Box<dyn Error>> {
    let bytes = hex::decode(hex_str)?;
    let mut array = [0u32; 8];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        array[i] = u32::from_be_bytes(chunk.try_into()?);
    }
    Ok(array)
}

pub fn load_elf(elf_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    fs::read(elf_path).map_err(|e| e.into())
}

pub fn serialize_guest_input<T: serde::Serialize>(
    data: &T,
    filename: &str,
) -> Result<(), Box<dyn Error>> {
    let serialized_data = bincode::serialize(data)?;
    let mut file = File::create(filename)?;
    file.write_all(&serialized_data)?;
    Ok(())
}
