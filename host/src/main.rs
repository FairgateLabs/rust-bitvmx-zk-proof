use std::io::Write;

use host::{prove_stark, verify_stark, prove_snark};
use clap::{Parser, Subcommand};
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
    ProveStark{
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
    VerifyStark{
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
    },

    /// Dump the ELF_ID that will be used as part of the groth proof
    DumpId {
        /// ID file
        #[arg(short, long, value_name = "FILE")]
        output: String,
    }



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
        Some(Commands::ProveStark { input, output, json }) => {
            let mut file = create_or_open_file(json);
            prove_stark(*input, &output);

            let json_result = json!({
                "type": "ProveStarkResult",
                "data": true,
            });

            file.write_all(json_result.to_string().as_bytes())
                .expect("Failed to write JSON to file");

        },
        Some(Commands::VerifyStark { input }) => {
            verify_stark(&input)
        },
        Some(Commands::ProveSnark { input, json}) => {
            let mut file = create_or_open_file(json);
            let snark_seal_data= prove_snark(&input);

            let json_result = json!({
                "type": "ProveSnarkResult",
                "data": snark_seal_data,
            });

            println!("The proof was executed, and the seal was saved");
            file.write_all(json_result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        },
        Some(Commands::DumpId {output}) => {
            let mut json = JsonValue::new_array();
            for value in methods::BITVMX_ID.iter() {
                let _ = json.push(*value);
            }
            println!("ID: {}", json.pretty(2));

            let path = std::path::Path::new(output);
            std::fs::write(path, json.dump()).unwrap();

        },
        None => {
         println!("No command provided");
        },
    };

}

fn create_or_open_file(file_path: &str) -> std::fs::File {
    std::fs::OpenOptions::new()
        .create(true) // create if it doesn't exist
        .write(true) // enable write
        .truncate(true) // clear existing content
        .open(file_path)
        .expect("Failed to open or create file")
}