use host::{prove_stark, verify_stark, prove_snark};
use clap::{Parser, Subcommand};
use json::JsonValue;
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

        /// Snark seal file
        #[arg(short, long, value_name = "FILE")]
        output: String,
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
        Some(Commands::ProveStark { input, output }) => {
            prove_stark(*input, &output)
        },
        Some(Commands::VerifyStark { input }) => {
            verify_stark(&input)
        },
        Some(Commands::ProveSnark { input, output }) => {
            prove_snark(&input, &output)

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