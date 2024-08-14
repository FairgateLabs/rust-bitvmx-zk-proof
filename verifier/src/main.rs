use verifier::cli;
use risc0_zkp::verify::VerificationError;

fn main() -> Result<(), VerificationError> {
    cli::run()
}