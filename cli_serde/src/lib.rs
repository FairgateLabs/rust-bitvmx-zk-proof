use bincode;
use hex;
use serde;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;

pub fn serialize_image_id(image_id: [u32; 8]) -> String {
    let bytes = image_id
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    hex::encode(bytes)
}

pub fn deserialize_image_id(hex_str: &str) -> Result<[u32; 8], Box<dyn Error>> {
    let bytes: [u8; 32] = hex::decode(hex_str)?
        .try_into()
        .map_err(|_| "image ID must contain exactly 32 bytes")?;
    let mut array = [0u32; 8];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        array[i] = u32::from_le_bytes(chunk.try_into()?);
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

#[cfg(test)]
mod tests {
    use super::{deserialize_image_id, serialize_image_id};

    #[test]
    fn image_id_uses_risc0_canonical_byte_order() {
        let image_id = [
            0x3482_1445,
            0xe5b1_2da4,
            0xb4aa_e547,
            0x1a2c_6aa9,
            0xb51d_da83,
            0xddbd_87a1,
            0x429c_d66b,
            0x9c5a_2e93,
        ];
        let canonical = "45148234a42db1e547e5aab4a96a2c1a83da1db5a187bddd6bd69c42932e5a9c";

        assert_eq!(serialize_image_id(image_id), canonical);
        assert_eq!(deserialize_image_id(canonical).unwrap(), image_id);
    }

    #[test]
    fn image_id_rejects_an_invalid_length() {
        assert!(deserialize_image_id("00").is_err());
    }
}
