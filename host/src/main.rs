use std::io::{Read, Write};

use clap::{Parser, Subcommand};
use cli_serde::{deserialize_image_id, load_elf};
use host::{prove_snark, prove_stark, verify_stark};
use risc0_zkvm::compute_image_id;
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
        #[arg(short, long, value_name = "INPUT_FILE")]
        input: String,

        /// ELF file path
        #[arg(short, long, value_name = "ELF_FILE")]
        elf: String,

        /// Output Proof file
        #[arg(short, long, value_name = "OUTPUT_FILE")]
        output: String,

        /// Output JSON file
        #[arg(short, long, value_name = "JSON_FILE")]
        json: Option<String>,
    },

    /// Verify the stark proof
    VerifyStark {
        /// Image id
        #[arg(short, long, value_name = "IMAGE_ID")]
        image_id: String,

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
        /// ELF file path
        #[arg(short, long, value_name = "ELF_FILE")]
        elf: String,

        /// Output ID file
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
            elf,
            output,
            json,
        }) => {
            let result = prove_stark(input, &elf, output);
            match json {
                Some(json) => {
                    let mut file = create_or_open_file(json, true);

                    let json_result = match result {
                        Ok(_) => serde_json::to_string(&ResultType::ProveResult {
                            seal: Vec::new(),
                            journal: Vec::new(),
                            status: "OK".to_string(),
                        }),
                        Err(e) => serde_json::to_string(&ResultType::ProveResult {
                            seal: Vec::new(),
                            journal: Vec::new(),
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
        Some(Commands::VerifyStark { input, image_id }) => {
            let image_id = deserialize_image_id(image_id).expect("Invalid image id");
            match verify_stark(image_id, &input) {
                Ok(_) => println!("Stark proof verified successfully"),
                Err(e) => println!("Failed to verify stark proof: {}", e),
            }
        }
        Some(Commands::ProveSnark {
            input,
            json,
            json_input,
        }) => {
            match json_input {
                Some(input_json_file) => validate_json_status(input_json_file),
                None => {}
            };

            let mut file = create_or_open_file(json, true);
            let snark_seal_result = prove_snark(&input);

            let json_result = match snark_seal_result {
                Ok((vec, journal)) => serde_json::to_string(&ResultType::ProveResult {
                    seal: vec,
                    journal,
                    status: "OK".to_string(),
                }),
                Err(e) => serde_json::to_string(&ResultType::ProveResult {
                    seal: Vec::new(),
                    journal: Vec::new(),
                    status: e,
                }),
            }
            .expect("Failed to serialize result to JSON");

            file.write_all(json_result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::DumpId { elf, output }) => {
            let elf_data = load_elf(elf).expect("Failed to load ELF file");
            let image_id = compute_image_id(&elf_data).expect("Failed to compute image ID");

            let id_bytes: Vec<u8> = image_id.as_bytes().to_vec();
            let hex_str = hex::encode(&id_bytes);
            println!("ID: {}", hex_str);

            let path = std::path::Path::new(output);
            std::fs::write(path, &hex_str).expect("Failed to write ID to file");
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
