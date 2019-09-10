#!/bin/bash
set -eu -o pipefail

# Required vars
SALT_ARCHIVE=${salt_content_archive}
SALT_DIR="/srv/salt"
ARCHIVE_FILE_NAME="salt_formula.zip"

# Standard aws envs
export AWS_DEFAULT_REGION=$(curl -sSL http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')

yum install unzip jq -y

echo "[appscript]: Ensuring default salt srv location exists, $SALT_DIR..."
mkdir -p $SALT_DIR

echo "[appscript]: Download salt formula archive file from s3://$SALT_ARCHIVE..."
aws s3 cp "s3://$SALT_ARCHIVE" $ARCHIVE_FILE_NAME

echo "[appscript]: Unzip salt formula archive file to $SALT_DIR"
unzip $ARCHIVE_FILE_NAME -d $SALT_DIR

echo "[appscript]: Remove salt formula archive file $ARCHIVE_FILE_NAME"
rm $ARCHIVE_FILE_NAME

echo "[appscript]: Configuring salt to read ec2 metadata into grains..."
echo "metadata_server_grains: True" > /etc/salt/minion.d/metadata.conf

echo "[appscript]: Setting required salt grains for vault..."
salt-call --local grains.setval vault ${salt_grains_json}

echo "[appscript]: Update minion config to allow module.run..."
printf 'use_superseded:\n  - module.run\n' >> /etc/salt/minion

echo "[appscript]: Print out salt versions report"
salt-call --local --versions-report

echo "[appscript]: Updating salt states/modules/utils/grains..."
salt-call --local saltutil.sync_all

echo "[appscript]: Retrieving path for directory storing log files..."
export LOGS_DIR=$(salt-call --local grains.get 'vault:logs_path' --output=json | jq .[] -r)

echo "[appscript]: Ensuring logs dir location exists, $LOGS_DIR..."
mkdir -p $LOGS_DIR

echo "[appscript]: Installing vault and configuring service, firewall..."
salt-call --local --retcode-passthrough state.sls vault -l info 2>&1 | tee $LOGS_DIR/salt_call.log

echo "[appscript]: Initializing vault..."
salt-call --local --retcode-passthrough state.sls vault.initialize -l info 2>&1 | tee $LOGS_DIR/initialize.log

echo "[appscript]: Sync configurations with the vault..."
export SSM_PATH=$(salt-call --local grains.get 'vault:ssm_path' --output=json | jq .[] -r)
export VAULT_TOKEN=$(aws ssm get-parameter --name /"$SSM_PATH"/root_token --with-decryption --query 'Parameter.Value' | tr -d '"')
salt-call --local --retcode-passthrough state.sls vault.sync -l info 2>&1 | tee $LOGS_DIR/sync_config.log

echo "[appscript]: Retrieving Vault's status"
# Vault local address
export API_PORT=$(salt-call --local grains.get 'vault:api_port' --output=json | jq .[])
export VAULT_ADDR=http://127.0.0.1:$API_PORT
vault status

echo "[appscript]: Completed appscript vault successfully!"
