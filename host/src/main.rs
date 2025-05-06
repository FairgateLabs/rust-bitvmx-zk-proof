use std::io::{Read, Write};

use clap::{Parser, Subcommand};
use host::{prove_snark, prove_stark, verify_stark};
use json::JsonValue;
use tracing_subscriber::EnvFilter;
use zk_result::ResultType;

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
        json: Option<String>,
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
            let result = prove_stark(*input, output);
            match json {
                Some(json) => {
                    let mut file = create_or_open_file(json, true);

                    let json_result = match result {
                        Ok(_) => serde_json::to_string(&ResultType::ProveResult {
                            seal: Vec::new(),
                            status: "OK".to_string(),
                        }),
                        Err(e) => serde_json::to_string(&ResultType::ProveResult {
                            seal: Vec::new(),
                            status: e,
                        }),
                    }
                    .expect("Failed to serialize result to JSON");

                    file.write_all(json_result.as_bytes())
                        .expect("Failed to write JSON to file");
                }
                None => {
                    if result.is_err() {
                        println!("Error: {}", result.unwrap_err());
                    }
                }
            }
        }
        Some(Commands::VerifyStark { input }) => verify_stark(&input),
        Some(Commands::ProveSnark {
            input,
            json,
            json_input,
        }) => {
            match json_input {
                Some(input_json_file) => validate_json_status(input_json_file),
                None => {},
            };
            
            let mut file = create_or_open_file(json, true);
            let snark_seal_result = prove_snark(&input);

            let json_result = match snark_seal_result {
                Ok(vec) => serde_json::to_string(&ResultType::ProveResult {
                    seal: vec,
                    status: "OK".to_string(),
                }),
                Err(e) => serde_json::to_string(&ResultType::ProveResult {
                    seal: Vec::new(),
                    status: e,
                }),
            }
            .expect("Failed to serialize result to JSON");

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

fn validate_json_status(json: &String) {
    let mut file = create_or_open_file(&json, false);

    let mut json_content = String::new();
    file.read_to_string(&mut json_content).unwrap();
    let result = ResultType::from_json_string(json_content).unwrap();

    if result.get_status() != "OK" {
        panic!("Status is not OK: {}", result.get_status());
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
            .expect("Failed to open or create file"),
    }
}
