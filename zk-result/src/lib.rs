use serde::{Deserialize, Serialize};
//TODO: Modify the ResultType to have multiple variants, now kind of obsolete

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ResultType {
    ProveResult { seal: Vec<u8>, journal: Vec<u8>, status: String },
}

impl ResultType {
    pub fn from_json_string(json: String) -> Result<Self, String> {
        let value = serde_json::from_str::<serde_json::Value>(&json)
            .map_err(|_| format!("Failed to parse JSON string: {}", json))?;

        let result: Self = serde_json::from_value(value)
            .map_err(|_| format!("Failed to deserialize JSON value"))?;

        Ok(result)
    }

    pub fn get_seal(&self) -> Vec<u8> {
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
