use clap::{Parser, Subcommand};

use crate::{template_setup, show_claim, verify, template_proof};
use risc0_zkp::verify::VerificationError;


#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {

    /// Generate the claim to be verified
    GenerateClaim {

        /// File name with the dumped image id
        #[arg(short, long, value_name = "FILE", required=true)]
        image_id: String,

        /// Expected journal produces by the stark
        #[arg(short, long, value_delimiter=',', num_args = 1.., required=true)]
        journal: Vec<u8>,
    },

    /// Verify the claim
    Verify {
        /// File name with the dumped image id
        #[arg(short, long, value_name = "FILE", required=true)]
        image_id: String,

        /// Expected journal produces by the stark
        #[arg(short, long, value_delimiter=',', num_args = 1.., required=true)]
        journal: Vec<u8>,

        /// Groth16 proof file
        #[arg(short, long, value_name = "FILE", required=true)]
        seal: String,
    },

    TemplateSetup {

        /// File name with the dumped image id
        #[arg(short, long, value_name = "FILE", required=true)]
        image_id: String,

        /// Initial template file
        #[arg(short, long, value_name = "FILE", required=true)]
        template: String,

        /// Output file
        #[arg(short, long, value_name = "FILE", required=true)]
        output: String,

    },

    TemplateProof {
        
        /// Expected journal produces by the stark
        #[arg(short, long, value_delimiter=',', num_args = 1.., required=true)]
        journal: Vec<u8>,

        /// Groth16 proof file
        #[arg(short, long, value_name = "FILE", required=true)]
        seal: String,

        /// Initial template file
        #[arg(short, long, value_name = "FILE", required=true)]
        template: String,

        /// Output file
        #[arg(short, long, value_name = "FILE", required=true)]
        output: String,

    },
}

pub fn run() -> Result<(), VerificationError> {
    
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::GenerateClaim { image_id, journal }) => {
            show_claim(image_id, journal);
        },
        Some(Commands::Verify { image_id, journal, seal} ) => {
            verify(image_id, journal, seal)?;
        },
        Some(Commands::TemplateSetup { image_id, template, output }) => {
            template_setup(image_id, template, output)
        },
        Some(Commands::TemplateProof { journal, seal, template, output}) => {
            template_proof(journal, seal, template, output)
        },

        None => {
            println!("No command provided");
        }

    }

    Ok(())

}
