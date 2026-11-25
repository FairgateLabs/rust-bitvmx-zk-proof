#!/bin/sh
# Builds the prover image (AMI) of the job dispatcher from scratch with one command, from any machine with git and the
# AWS CLI: it launches an instance with an NVIDIA T4 GPU from Ubuntu 24.04, runs scripts/setup-prover.sh on it through
# SSM, proves a test input when one is given, creates the AMI and terminates the instance.
#
# Usage: [VARIABLE=value ...] scripts/build-ami.sh
#
# Required:
#   BUCKET            S3 bucket for the build inputs and the SSM logs.
#   INSTANCE_PROFILE  name of an instance profile with AmazonSSMManagedInstanceCore and read and write access to
#                     BUCKET.
#   GUEST_BIN         guest .bin to install in guests/, with the name that the prove jobs use (scripts/build-guest.sh
#                     writes it).
# Optional:
#   AWS_REGION        region; the default region of the AWS CLI when unset.
#   TEST_INPUT        input of the guest. When set, the instance proves it before the AMI is created.
#   REF               git ref of this repository to build (default HEAD). Only committed changes are built.
#   INSTANCE_TYPES    instance types to try, in order (default "g4dn.2xlarge g4dn.xlarge"). They all need the same
#                     GPU, since the cuda kernels are built for the GPU of the build instance.
#   RETRY_MINUTES     how long to keep asking for each type, every 2 minutes, while no zone has capacity (default 10).
#   AMI_NAME          name of the AMI (default zkp-prover-gpu-<date>-<commit>).
#   VOLUME_GB         size of the root volume (default 60).
#   WATCHDOG_MINUTES  the build instance powers off, and so terminates, this many minutes after each boot (default
#                     180), even if this script stops.
#   KEEP_INSTANCE     1 keeps the instance when the build fails, to look into it (default 0).
#
# The account needs a default VPC: the instance gets the default subnet of each zone it tries.

set -eu

: "${BUCKET:?Set BUCKET}"
: "${INSTANCE_PROFILE:?Set INSTANCE_PROFILE}"
: "${GUEST_BIN:?Set GUEST_BIN}"
TEST_INPUT=${TEST_INPUT:-}
REF=${REF:-HEAD}
INSTANCE_TYPES=${INSTANCE_TYPES:-g4dn.2xlarge g4dn.xlarge}
RETRY_MINUTES=${RETRY_MINUTES:-10}
VOLUME_GB=${VOLUME_GB:-60}
WATCHDOG_MINUTES=${WATCHDOG_MINUTES:-180}
KEEP_INSTANCE=${KEEP_INSTANCE:-0}

[ -f "$GUEST_BIN" ] || { echo "GUEST_BIN $GUEST_BIN does not exist" >&2; exit 1; }
[ -z "$TEST_INPUT" ] || [ -f "$TEST_INPUT" ] || { echo "TEST_INPUT $TEST_INPUT does not exist" >&2; exit 1; }

cd "$(dirname "$0")/.."
COMMIT=$(git rev-parse --short "$REF")
STAMP=$(date -u +%Y%m%d-%H%M%S)
AMI_NAME=${AMI_NAME:-zkp-prover-gpu-$STAMP-$COMMIT}
PREFIX=ami-builds/$STAMP-$COMMIT
GUEST_NAME=$(basename "$GUEST_BIN")
WORK=$(mktemp -d)
INSTANCE_ID=
DONE=0

log() {
    echo "$(date -u +%H:%M:%S) $*"
}

cleanup() {
    if [ -n "$INSTANCE_ID" ]; then
        if [ "$DONE" = 1 ] || [ "$KEEP_INSTANCE" != 1 ]; then
            log "Terminating $INSTANCE_ID"
            aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null || true
        else
            log "Keeping $INSTANCE_ID to look into it; terminate it when done"
        fi
    fi
    aws s3 rm --quiet --recursive "s3://$BUCKET/$PREFIX/inputs/" || true
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

log "Building $AMI_NAME from $REF ($COMMIT) with guest $GUEST_NAME"

git archive --format=tar.gz -o "$WORK/source.tar.gz" "$REF"
aws s3 cp --quiet "$WORK/source.tar.gz" "s3://$BUCKET/$PREFIX/inputs/source.tar.gz"
aws s3 cp --quiet "$GUEST_BIN" "s3://$BUCKET/$PREFIX/inputs/$GUEST_NAME"
[ -z "$TEST_INPUT" ] || aws s3 cp --quiet "$TEST_INPUT" "s3://$BUCKET/$PREFIX/inputs/test-input.bin"

# The instance downloads the inputs with curl, since it has no AWS CLI before setup-prover.sh installs it.
presign() {
    aws s3 presign "s3://$BUCKET/$PREFIX/inputs/$1" --expires-in 21600
}
SOURCE_URL=$(presign source.tar.gz)
GUEST_URL=$(presign "$GUEST_NAME")
TEST_URL=
[ -z "$TEST_INPUT" ] || TEST_URL=$(presign test-input.bin)

BASE_AMI=$(aws ssm get-parameter --query Parameter.Value --output text \
    --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id)
ROOT_DEVICE=$(aws ec2 describe-images --image-ids "$BASE_AMI" --query 'Images[0].RootDeviceName' --output text)
log "Base image $BASE_AMI (Ubuntu 24.04)"

# The watchdog powers off the instance after each boot; the instance terminates on power off. It is removed before the
# AMI is created, so the provers do not have it.
cat >"$WORK/user-data" <<EOF
#cloud-config
write_files:
  - path: /etc/systemd/system/build-watchdog.service
    content: |
      [Unit]
      Description=Power off the image build instance when the build takes too long
      After=multi-user.target
      [Service]
      Type=oneshot
      ExecStart=/sbin/shutdown -P +$WATCHDOG_MINUTES
      [Install]
      WantedBy=multi-user.target
runcmd:
  - [systemctl, enable, --now, build-watchdog.service]
EOF

launch() {
    aws ec2 run-instances --image-id "$BASE_AMI" --instance-type "$1" --placement "AvailabilityZone=$2" \
        --iam-instance-profile "Name=$INSTANCE_PROFILE" \
        --block-device-mappings "[{\"DeviceName\":\"$ROOT_DEVICE\",\"Ebs\":{\"VolumeSize\":$VOLUME_GB,\"VolumeType\":\"gp3\",\"DeleteOnTermination\":true}}]" \
        --instance-initiated-shutdown-behavior terminate --metadata-options HttpTokens=required \
        --user-data "file://$WORK/user-data" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$AMI_NAME-build}]" \
        --query 'Instances[0].InstanceId' --output text 2>"$WORK/launch.err"
}

# Each type is asked in every zone that offers it, every 2 minutes for RETRY_MINUTES, before moving to the next type.
for type in $INSTANCE_TYPES; do
    zones=$(aws ec2 describe-instance-type-offerings --location-type availability-zone \
        --filters "Name=instance-type,Values=$type" --query 'InstanceTypeOfferings[].Location' --output text)
    deadline=$(($(date +%s) + RETRY_MINUTES * 60))
    while :; do
        for zone in $zones; do
            if id=$(launch "$type" "$zone"); then
                INSTANCE_ID=$id
                log "Launched $INSTANCE_ID ($type in $zone)"
                break 3
            fi
            if grep -qE 'InsufficientInstanceCapacity|VcpuLimitExceeded|Unsupported' "$WORK/launch.err"; then
                log "No $type in $zone: $(grep -oE '[A-Za-z]+(Capacity|Exceeded|Unsupported)' "$WORK/launch.err" | head -n 1)"
            else
                cat "$WORK/launch.err" >&2
                exit 1
            fi
        done
        [ $(($(date +%s) + 120)) -lt "$deadline" ] || break
        sleep 120
    done
done
[ -n "$INSTANCE_ID" ] || { log "No capacity for any of: $INSTANCE_TYPES"; exit 1; }

aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

wait_ssm() {
    i=0
    while [ "$i" -lt 60 ]; do
        status=$(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
            --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
        [ "$status" = Online ] && return 0
        sleep 10
        i=$((i + 1))
    done
    log "The instance did not connect to SSM"
    exit 1
}

# Runs a shell command on the instance through SSM and waits for it. The full output goes to
# s3://BUCKET/PREFIX/logs/<command id>/.
run_step() {
    name=$1
    command=$2
    timeout=$3
    log "Step $name"
    command_id=$(aws ssm send-command --instance-ids "$INSTANCE_ID" --document-name AWS-RunShellScript \
        --comment "$AMI_NAME $name" --timeout-seconds 3600 \
        --parameters "{\"commands\":[\"$command\"],\"executionTimeout\":[\"$timeout\"]}" \
        --output-s3-bucket-name "$BUCKET" --output-s3-key-prefix "$PREFIX/logs" \
        --query Command.CommandId --output text)
    start=$(date +%s)
    while :; do
        sleep 30
        status=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$INSTANCE_ID" \
            --query Status --output text 2>/dev/null || echo Pending)
        case $status in
        Success)
            log "Step $name done in $((($(date +%s) - start) / 60)) min"
            return 0
            ;;
        Failed | TimedOut | Cancelled | Cancelling)
            log "Step $name: $status. Last lines of the output:"
            aws ssm get-command-invocation --command-id "$command_id" --instance-id "$INSTANCE_ID" \
                --query StandardErrorContent --output text | tail -n 30 >&2
            log "Full output: s3://$BUCKET/$PREFIX/logs/$command_id/"
            exit 1
            ;;
        esac
        log "Step $name: $status, $((($(date +%s) - start) / 60)) min"
    done
}

wait_ssm

run_step system "set -e; mkdir -p /opt/build; cd /opt/build; curl -fsSL '$SOURCE_URL' -o source.tar.gz; mkdir -p src; tar -xzf source.tar.gz -C src; sh src/scripts/setup-prover.sh system" 3600

log "Rebooting to load the NVIDIA driver"
aws ec2 reboot-instances --instance-ids "$INSTANCE_ID"
sleep 90
wait_ssm

test_download=
test_arg=
if [ -n "$TEST_URL" ]; then
    test_download="curl -fsSL '$TEST_URL' -o test-input.bin;"
    test_arg=/opt/build/test-input.bin
fi
run_step build "set -e; cd /opt/build; curl -fsSL '$GUEST_URL' -o '$GUEST_NAME'; $test_download sh src/scripts/setup-prover.sh build /opt/build/source.tar.gz '/opt/build/$GUEST_NAME' $test_arg" 10800

# The pending power off of the watchdog keeps protecting the instance while the AMI is created without a reboot.
run_step finish "set -e; rm -rf /opt/build; systemctl disable build-watchdog.service; rm -f /etc/systemd/system/build-watchdog.service; cloud-init clean --logs; sync" 600

log "Creating $AMI_NAME"
AMI_ID=$(aws ec2 create-image --instance-id "$INSTANCE_ID" --name "$AMI_NAME" --no-reboot \
    --description "Prover image: $(git log -1 --format='%h %s' "$REF"), guest $GUEST_NAME" \
    --tag-specifications "ResourceType=image,Tags=[{Key=Name,Value=$AMI_NAME}]" \
    --query ImageId --output text)
while :; do
    state=$(aws ec2 describe-images --image-ids "$AMI_ID" --query 'Images[0].State' --output text)
    case $state in
    available) break ;;
    failed | error | invalid | deregistered)
        log "The AMI $AMI_ID is $state"
        exit 1
        ;;
    esac
    log "AMI $AMI_ID: $state"
    sleep 60
done

DONE=1
log "AMI $AMI_ID ($AMI_NAME) is available. Set it as ec2.image_id in the config of the job dispatcher."
