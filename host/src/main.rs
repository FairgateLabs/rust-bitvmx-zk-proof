use clap::{Parser, Subcommand};
use host::{prove_snark, prove_stark, verify_stark};
use json::JsonValue;
use tracing_subscriber::EnvFilter;
use cli_serde::deserialize_image_id;

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
        #[arg(short, long, value_name = "INPUT_FILE")]
        input: String,

        /// ELF file path
        #[arg(short, long, value_name = "ELF_FILE")]
        elf: String,

        /// Output Proof file
        #[arg(short, long, value_name = "OUTPUT_FILE")]
        output: String,
    },

    /// Verify the stark proof
    VerifyStark{
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

        /// Snark seal file
        #[arg(short, long, value_name = "FILE")]
        output: String,
    },

    /// Dump the ELF_ID that will be used as part of the groth proof
    DumpId {
        /// Serialized image id
        #[arg(short, long, value_name = "FILE")]
        id: String,

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
        Some(Commands::ProveStark { input, elf, output }) => {
            prove_stark(input, elf, &output)
        },
        Some(Commands::VerifyStark { image_id, input }) => {
            let image_id = deserialize_image_id(image_id).expect("Invalid image id");
            verify_stark(image_id, &input)
        },
        Some(Commands::ProveSnark { input, output }) => {
            prove_snark(&input, &output)

        },
        Some(Commands::DumpId {id: image_id, output}) => {
            let image_id = deserialize_image_id(image_id).expect("Invalid image id");

            let mut json = JsonValue::new_array();

            for value in image_id.iter() {
                let _ = json.push(*value);
            }
            println!("ID: {}", json.pretty(2));

            let path = std::path::Path::new(output);
            std::fs::write(path, json.dump()).unwrap();

        }
        None => {
         println!("No command provided");
        },
    };

}