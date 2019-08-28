#!/bin/bash
set -eu -o pipefail

# Required vars
SALT_ARCHIVE=${salt_content_archive}
CONFIGS_ARCHIVE=${vault_config_archive}
VAULT_VERSION=${vault_version}
DYNAMODB_TABLE=${dynamodb_table}
KMS_KEY_ID=${kms_key_id}
SSM_PATH=${ssm_path}

# Standard aws envs
export AWS_DEFAULT_REGION=$(curl -sSL http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//')

# Vault local address
export VAULT_ADDR=http://127.0.0.1:8200
SALT_DIR="/srv/salt"
CONFIGURATION_PATH="/etc/vault/configs"
ARCHIVE_FILE_NAME="salt_formula.zip"
CONFIGS_FILE_NAME="vault_configs.zip"

yum install unzip -y

echo "[appscript]: Ensuring default salt srv location exists, $SALT_DIR..."
mkdir -p $SALT_DIR

echo "[appscript]: Download salt formula archive file from s3://$SALT_ARCHIVE..."
aws s3 cp "s3://$SALT_ARCHIVE" $ARCHIVE_FILE_NAME

echo "[appscript]: Unzip salt formula archive file to $SALT_DIR"
unzip $ARCHIVE_FILE_NAME -d $SALT_DIR

echo "[appscript]: Remove salt formula archive file $ARCHIVE_FILE_NAME"
rm $ARCHIVE_FILE_NAME

echo "[appscript]: Updating salt grains..."
salt-call --local saltutil.sync_grains

echo "[appscript]: Configuring salt to read ec2 metadata into grains..."
echo "metadata_server_grains: True" > /etc/salt/minion.d/metadata.conf

echo "[appscript]: Setting required salt grains for vault..."
salt-call --local grains.setval vault \
"{'version':'$VAULT_VERSION', 'dynamodb_table':'$DYNAMODB_TABLE', 'kms_key_id':'$KMS_KEY_ID', 'region':'$AWS_DEFAULT_REGION', 'ssm_path': '$SSM_PATH', 'config_dir_path': '$CONFIGURATION_PATH'}"

echo "[appscript]: Update minion config to allow module.run..."
printf 'use_superseded:\n  - module.run\n' >> /etc/salt/minion

echo "[appscript]: Print out salt versions report"
salt-call --local --versions-report

echo "[appscript]: Updating salt states to include custom vault's states/modules..."
salt-call --local saltutil.sync_all

echo "[appscript]: Installing vault and configuring service, firewall..."
salt-call --local --retcode-passthrough state.sls vault -l info 2>&1 | tee /var/log/salt_vault.log

echo "[appscript]: Initializing vault..."
salt-call --local --retcode-passthrough state.sls vault.initialize -l info 2>&1 | tee /var/log/salt_vault_initialize.log

# Applying configurations per specific implementation
if [ "$CONFIGS_ARCHIVE" != "n/a" ];
then
  echo "[appscript]: Retrieving root token to assist configuration provisioning..."
  VAULT_TOKEN=$(aws ssm get-parameter --name /"$SSM_PATH"/root_token --with-decryption --query 'Parameter.Value' | tr -d '"')
  export VAULT_TOKEN

  echo "[appscript]: Ensuring default vault configs location exists, $CONFIGURATION_PATH..."
  mkdir -p $CONFIGURATION_PATH

  echo "[appscript]: Download vault configs archive file from s3://$CONFIGS_ARCHIVE..."
  aws s3 cp "s3://$CONFIGS_ARCHIVE" $CONFIGS_FILE_NAME

  echo "[appscript]: Unzip vault configs archive file to $CONFIGURATION_PATH..."
  unzip $CONFIGS_FILE_NAME -d $CONFIGURATION_PATH

  echo "[appscript]: Remove vault configs archive file $CONFIGS_FILE_NAME"
  rm $CONFIGS_FILE_NAME

  echo "[appscript]: Sync configurations with the vault..."
  salt-call --local --retcode-passthrough state.sls vault.sync -l info 2>&1 | tee /var/log/salt_vault_sync.log

else
  echo "[appscript]: No vault configurations provided. Skipping configuration vault step..."
fi

echo "[appscript]: Retrieving Vault's status"
vault status

echo "[appscript]: Completed appscript vault successfully!"
