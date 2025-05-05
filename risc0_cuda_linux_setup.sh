################################################################
# install rust with defaults
################################################################
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.bashrc

################################################################
# install Risc0
################################################################
curl -L https://risczero.com/install | bash
source ~/.bashrc
rzup install

# at this point, ZK proof generation should work via CPU already

################################################################
# install required Ubuntu Drivers (includes nvidia drivers)
################################################################
sudo apt install ubuntu-drivers-common
sudo ubuntu-drivers install

################################################################
# install required CUDA drivers
################################################################
# note1: Ris0 steps did NOT work on AWS (https://dev.risczero.com/api/generating-proofs/local-proving)
# note2: official Nvidia steps worked fine (https://developer.nvidia.com/cuda-downloads?target_os=Linux&target_arch=x86_64&Distribution=Ubuntu&target_version=22.04&target_type=deb_network)
# note4: check update policy (https://docs.nvidia.com/cuda/cuda-installation-guide-linux/#meta-packages)
# note3: this installation takes a while
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
rm cuda-keyring_1.1-1_all.deb
sudo apt-get update
sudo apt-get install cuda-toolkit
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc