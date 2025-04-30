use std::io::Write;

use clap::{Parser, Subcommand};
use host::{prove_snark, prove_stark, verify_stark};
use json::JsonValue;
use serde_json::json;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate the stark proof
    ProveStark {
        /// Input that proves the stark
        #[arg(short, long)]
        input: u32,

        /// Output Proof file
        #[arg(short, long, value_name = "FILE")]
        output: String,

        /// Output JSON file
        #[arg(short, long, value_name = "JSON_FILE")]
        json: String,
    },

    /// Verify the stark proof
    VerifyStark {
        /// Stark proof file
        #[arg(short, long, value_name = "FILE")]
        input: String,
    },

    /// Convert a stark proof to a groth16 proof
    ProveSnark {
        /// Stark proof file
        #[arg(short, long, value_name = "FILE")]
        input: String,

        /// Output JSON file
        #[arg(short, long, value_name = "JSON_FILE")]
        json: String,

        /// JSON Input Condition File
        #[arg(short, long, value_name = "JSON_FILE")]
        json_input: Option<String>,
    },

    /// Dump the ELF_ID that will be used as part of the groth proof
    DumpId {
        /// ID file
        #[arg(short, long, value_name = "FILE")]
        output: String,
    },
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

fn main() {
    init_logging();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::ProveStark {
            input,
            output,
            json,
        }) => {
            let mut file = create_or_open_file(json, true);
            let result = prove_stark(*input, &output);

            let json_result = match result {
                Ok(_) => {
                    json!({
                        "type": "ProveResult",
                        "data": {
                            "vec": Vec::<u8>::new(),
                            "status": "OK",
                        },
                    })
                }
                Err(e) => {
                    json!({
                        "type": "ProveResult",
                        "data": {
                            "vec": Vec::<u8>::new(),
                            "status": e.to_string(),
                        },
                    })
                }
            };

            file.write_all(json_result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::VerifyStark { input }) => verify_stark(&input),
        Some(Commands::ProveSnark { input, json, json_input }) => {
            let json_input = match json_input {
                Some(input) => input,
                None => json
            };
            
            validate_json_status(json_input);
            let mut file = create_or_open_file(json, true);
            let snark_seal_result = prove_snark(&input);

            let json_result = match snark_seal_result {
                Ok(vec) => {
                    json!({
                        "type": "ProveResult",
                        "data": {
                            "vec": vec,
                            "status": "OK",
                        },
                    })
                }
                Err(e) => {
                    json!({
                        "type": "ProveResult",
                        "data": {
                            "vec": Vec::<u8>::new(),
                            "status": e,
                        },
                    })
                }
            };

            file.write_all(json_result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::DumpId { output }) => {
            let mut json = JsonValue::new_array();
            for value in methods::BITVMX_ID.iter() {
                let _ = json.push(*value);
            }
            println!("ID: {}", json.pretty(2));

            let path = std::path::Path::new(output);
            std::fs::write(path, json.dump()).unwrap();
        }
        None => {
            println!("No command provided");
        }
    };
}

fn validate_json_status(json: &String){
    let file = create_or_open_file(&json, false);
    let json_content: serde_json::Value = serde_json::from_reader(file).expect("Failed to read JSON file");
    if let Some(status) = json_content["data"]["status"].as_str() {
        if status != "OK" {
            panic!("Status is not OK: {}", status);
        }
    }
}

fn create_or_open_file(file_path: &str, write: bool) -> std::fs::File {
    match write {
        true => std::fs::OpenOptions::new()
                    .create(true) // create if it doesn't exist
                    .write(true) // enable write
                    .truncate(true) // clear existing content
                    .open(file_path)
                    .expect("Failed to open or create file"),
        false => std::fs::OpenOptions::new()
                    .read(true) // enable read
                    .open(file_path)
                    .expect("Failed to open or create file")
    }
}