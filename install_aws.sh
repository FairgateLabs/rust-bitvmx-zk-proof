if ! command -v aws >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y unzip curl
    tmpdir="$(mktemp -d)"
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "$tmpdir/awscliv2.zip"
    unzip -q "$tmpdir/awscliv2.zip" -d "$tmpdir"
    sudo "$tmpdir/aws/install" --update
    rm -rf "$tmpdir"
fi