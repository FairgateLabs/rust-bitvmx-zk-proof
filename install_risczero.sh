## Install RiscZero
curl -L https://risczero.com/install | bash
source ~/.bashrc
cargo install cargo-binstall
cargo binstall cargo-risczero --version 3.0.4 -y
rzup install
cargo build --release