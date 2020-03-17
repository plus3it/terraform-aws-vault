#!/bin/bash
set -eu -o pipefail

# Required vars
# shellcheck disable=SC2154
SALT_ARCHIVE=${salt_content_archive}
# shellcheck disable=SC2154
PILLAR_ARCHIVE=${pillar_archive}
SALT_DIR="/srv/salt"
PILLAR_DIR="/srv/pillar"
ARCHIVE_FILE_NAME="salt_formula.zip"
PILLAR_FILE_NAME="pillar.zip"

# Standard aws envs
AWS_DEFAULT_REGION=$(curl -sSL http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')
export AWS_DEFAULT_REGION

yum install unzip jq -y

echo "[appscript]: Ensuring default salt srv location exists, $SALT_DIR..."
mkdir -p $SALT_DIR

echo "[appscript]: Download salt formula archive file from $SALT_ARCHIVE..."
aws s3 cp "$SALT_ARCHIVE" $ARCHIVE_FILE_NAME

echo "[appscript]: Unzip salt formula archive file to $SALT_DIR"
unzip $ARCHIVE_FILE_NAME -d $SALT_DIR

echo "[appscript]: Remove salt formula archive file $ARCHIVE_FILE_NAME"
rm $ARCHIVE_FILE_NAME

echo "[appscript]: Ensuring default pillar location exists, $PILLAR_DIR..."
mkdir -p $PILLAR_DIR

echo "[appscript]: Download pillar archive file from $PILLAR_ARCHIVE..."
aws s3 cp "$PILLAR_ARCHIVE" $PILLAR_FILE_NAME

echo "[appscript]: Unzip pillar archive file to $PILLAR_DIR"
unzip $PILLAR_FILE_NAME -d $PILLAR_DIR

echo "[appscript]: Remove pillar archive file $PILLAR_FILE_NAME"
rm $PILLAR_FILE_NAME

echo "[appscript]: Configuring salt to read ec2 metadata into grains..."
echo "metadata_server_grains: True" > /etc/salt/minion.d/metadata.conf

echo "[appscript]: Print out salt versions report"
salt-call --local --versions-report

echo "[appscript]: Updating salt states/modules/utils/grains..."
salt-call --local saltutil.sync_all

echo "[appscript]: Retrieving path for directory storing log files..."
LOGS_DIR=$(salt-call --local pillar.get 'vault:lookup:logs_dir' --output=json | jq .[] -r)
export LOGS_DIR

echo "[appscript]: Retrieving logs path from pillar..."
LOGS_PATH=$(salt-call --local pillar.get 'vault:lookup:logs_path' --output=json | jq .[] -r)
export LOGS_PATH

echo "[appscript]: Ensuring logs dir location exists, $LOGS_DIR..."
mkdir -p "$LOGS_DIR"

echo "[appscript]: Installing vault and configuring service, firewall..."
salt-call --local --retcode-passthrough state.sls vault -l info 2>&1 | tee "$LOGS_PATH.log"

echo "[appscript]: Initializing vault..."
salt-call --local --retcode-passthrough state.sls vault.initialize -l info 2>&1 | tee "$LOGS_PATH.initialize.log"

echo "[appscript]: Sync configurations with the vault..."
SSM_PATH=$(salt-call --local pillar.get 'vault:lookup:ssm_path' --output=json | jq .[] -r)
export SSM_PATH

VAULT_TOKEN=$(aws ssm get-parameter --name /"$SSM_PATH"/root_token --with-decryption --query 'Parameter.Value' | tr -d '"')
export VAULT_TOKEN

salt-call --local --retcode-passthrough state.sls vault.sync -l info 2>&1 | tee "$LOGS_PATH.sync.log"

echo "[appscript]: Retrieving Vault's status"
# Get api port for vault server
API_PORT=$(salt-call --local pillar.get 'vault:lookup:api_port' --output=json | jq .[])
export API_PORT

# Exports Vault's address
VAULT_ADDR=http://127.0.0.1:$API_PORT
export VAULT_ADDR

# Retrieves Vault's status
vault status

echo "[appscript]: Completed appscript vault successfully!"
