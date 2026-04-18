use serde::{Deserialize, Serialize};
//TODO: Modify the ResultType to have multiple variants, now kind of obsolete

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ResultType {
    ProveResult {
        seal: Vec<u8>,
        journal: Vec<u8>,
        status: String,
    },
}

impl ResultType {
    pub fn from_json_string(json: String) -> Result<Self, String> {
        let value = serde_json::from_str::<serde_json::Value>(&json)
            .map_err(|_| format!("Failed to parse JSON string: {}", json))?;

        let result: Self = serde_json::from_value(value)
            .map_err(|_| format!("Failed to deserialize JSON value"))?;

        Ok(result)
    }

    pub fn get_seal(&self) -> Result<Vec<Vec<u8>>, String> {
        match self {
            ResultType::ProveResult { seal, .. } => {
                ResultSeal::decode(&seal).and_then(|s| Ok(s.generate_proof_bytes_from_seal()))
            }
        }
    }

    pub fn get_seal_full(&self) -> Vec<u8> {
        match self {
            ResultType::ProveResult { seal, .. } => seal.clone(),
        }
    }

    pub fn get_journal(&self) -> Vec<u8> {
        match self {
            ResultType::ProveResult { journal, .. } => journal.clone(),
        }
    }

    pub fn get_status(&self) -> String {
        match self {
            ResultType::ProveResult { status, .. } => status.clone(),
        }
    }
}

// The seal structure is copied from RISC Zero codebase and mofified to satisfy the groth16 verifier
// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

struct ResultSeal {
    a: Vec<Vec<u8>>,
    b: Vec<Vec<Vec<u8>>>,
    c: Vec<Vec<u8>>,
}

impl ResultSeal {
    const ELEMENT_SIZE: usize = 32;
    const G1_GROUP_SIZE: usize = Self::ELEMENT_SIZE * 2;
    const G2_GROUP_SIZE: usize = Self::ELEMENT_SIZE * 4;
    const SIZE: usize = Self::G1_GROUP_SIZE * 2 + Self::G2_GROUP_SIZE;

    /// Decode a seal from raw bytes.
    pub fn decode(data: &[u8]) -> Result<ResultSeal, String> {
        if data.len() != Self::SIZE {
            return Err("Data length mismatch".to_string());
        }

        let mut offset = 0;
        let mut a = Vec::with_capacity(2);
        let mut b = Vec::with_capacity(2);
        let mut c = Vec::with_capacity(2);

        // Deserialize 'a'
        for _ in 0..2 {
            a.push(data[offset..offset + Self::ELEMENT_SIZE].to_vec());
            offset += Self::ELEMENT_SIZE;
        }

        // Deserialize 'b'
        for _ in 0..2 {
            let mut sub_vec = Vec::with_capacity(2);
            for _ in 0..2 {
                sub_vec.push(data[offset..offset + Self::ELEMENT_SIZE].to_vec());
                offset += Self::ELEMENT_SIZE;
            }
            b.push(sub_vec);
        }

        // Deserialize 'c'
        for _ in 0..2 {
            c.push(data[offset..offset + Self::ELEMENT_SIZE].to_vec());
            offset += Self::ELEMENT_SIZE;
        }

        Ok(ResultSeal { a, b, c })
    }

    fn generate_proof_bytes_from_seal(&self) -> Vec<Vec<u8>> {
        let bytes_proof_a = Self::g1_to_c_bytes(self.a.clone());
        let bytes_proof_b = Self::g2_to_c_bytes(self.b.clone());
        let bytes_proof_c = Self::g1_to_c_bytes(self.c.clone());
        vec![bytes_proof_a, bytes_proof_b, bytes_proof_c]
    }

    fn g1_to_c_bytes(mut g1: Vec<Vec<u8>>) -> Vec<u8> {
        if g1[1][31] % 2 == 1 {
            g1[0][0] += 128;
        }
        g1[0].reverse();
        g1[0].clone()
    }

    fn g2_to_c_bytes(g2: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
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
}

#[cfg(test)]
mod test {

    use super::*;

    fn test_result() -> ResultType {
        let proof = ResultType::from_json_string(
        r#"{"type":"ProveResult","data":{"seal":[29,51,154,41,80,115,150,71,48,170,229,36,76,241,29,116,248,227,111,78,147,159,90,149,117,238,229,12,203,43,28,57,16,18,109,7,191,174,11,192,23,234,240,245,189,134,119,152,170,63,40,3,133,35,162,236,187,29,120,155,12,39,248,60,42,162,37,84,247,35,95,104,187,50,14,96,116,60,249,9,45,82,38,35,180,93,18,135,221,209,98,108,101,62,189,117,4,101,231,131,226,41,231,133,208,39,165,159,137,185,36,182,20,224,41,11,145,55,61,99,101,213,171,4,132,11,28,247,1,235,219,250,166,9,201,42,54,178,184,92,95,78,56,249,50,60,163,60,169,106,137,92,238,27,23,21,36,212,28,166,17,136,224,173,188,48,117,10,118,153,24,187,2,77,110,128,206,50,220,111,145,36,177,73,118,196,3,22,4,133,75,43,21,46,153,166,242,236,40,73,66,246,97,27,193,147,234,22,162,209,150,106,223,188,238,129,97,202,140,58,142,68,235,4,1,46,20,224,140,92,212,104,43,233,176,46,49,225,208,52,235,230,86,193,87,198,86,234,39,147,98,30,125,24,154,227],"journal":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,0,0,0,0,218,78,205,170,22,26,176,189,145,45,83,210,111,99,42,171,56,173,17,77,9,33,135,209,43,212,34,204,193,80,77,95,0,0,0,4,1,0,1,0],"status":"OK"}}"#.to_string()
        );
        proof.unwrap()
    }

    #[test]
    fn test_result_type_serialization() {
        let result = test_result();

        //from hex string to bytes
        let expected =  "391c2bcb0ce5ee75955a9f934e6fe3f8741df14c24e5aa3047967350299a331df71c0b8404abd565633d37910b29e014b624b9899fa527d085e729e283e7650475bd3e656c62d1dd87125db42326522d09f93c74600e32bb685f23f75425a2aa04eb448e3a8cca6181eebcdf6a96d1a216ea93c11b61f6424928ecf2a6992e95";
        let expected_bytes = hex::decode(expected).unwrap();

        assert_eq!(result.get_seal().unwrap().concat(), expected_bytes);
    }
}
