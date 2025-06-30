use risc0_zkp::verify::VerificationError;
use verifier::cli;

fn main() -> Result<(), VerificationError> {
    cli::run()
}
