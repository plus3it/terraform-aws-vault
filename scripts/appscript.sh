#!/bin/bash
set -eu -o pipefail

[[ $# -lt 5 ]] && {
    echo "Usage $0 <SALT_ARCHIVE> <VAULT_VERSION> <DYNAMODB_TABLE> <KMS_KEY_ID> <SSM_PATH>" >&2
    echo "  Example: $0 bucket-foo/randomid/salt.zip 1.1.3 vault-data-table bb0392ea-f31b-4ef2-af9e-be18661a8246 vault/dev/token" >&2
    exit 1
}

# Required vars
SALT_ARCHIVE=$1
VAULT_VERSION=$2
DYNAMODB_TABLE=$3
KMS_KEY_ID=$4
SSM_PATH=$5

# Internal vars
AWS_AZ=$(curl -sSL http://169.254.169.254/latest/meta-data/placement/availability-zone)
SALT_DIR="/srv/salt"
ARCHIVE_NAME="salt_formula.zip"

# Export standard aws envs
export AWS_DEFAULT_REGION=${AWS_AZ:0:${#AWS_AZ} - 1}

# Export Vault local address
export VAULT_ADDR=http://127.0.0.1:8200

echo "[appscript]: Ensuring default salt srv location exists, ${SALT_DIR}..."
mkdir -p ${SALT_DIR}

echo "[appscript]: Download salt formula archive file from s3://${SALT_ARCHIVE}..."
aws s3 cp "s3://${SALT_ARCHIVE}" ${ARCHIVE_NAME}

echo "[appscript]: Unzip salt formula archive file to ${SALT_DIR}"
yum install unzip -y
unzip ${ARCHIVE_NAME} -d ${SALT_DIR}

echo "[appscript]: Remove salt formula archive file ${ARCHIVE_NAME}"
rm ${ARCHIVE_NAME}

echo "[appscript]: Updating salt grains..."
salt-call --local saltutil.sync_grains

echo "[appscript]: Configuring salt to read ec2 metadata into grains..."
echo "metadata_server_grains: True" > /etc/salt/minion.d/metadata.conf

echo "[appscript]: Setting required salt grains for vault..."
salt-call --local grains.setval vault \
"{'version':'${VAULT_VERSION}', 'dynamodb_table':'${DYNAMODB_TABLE}', 'kms_key_id':'${KMS_KEY_ID}', 'region':'${AWS_DEFAULT_REGION}', 'ssm_path': '${SSM_PATH}'}"

echo "[appscript]: Applying the vault install and configure states..."
salt-call --local --retcode-passthrough state.sls vault -l info 2>&1 | tee /var/log/salt_vault.log

echo "[appscript]: Updating salt states to include custom vault's states..."
salt-call --local saltutil.sync_states

echo "[appscript]: Initializing the vault..."
salt-call --local --retcode-passthrough state.sls vault.initialize -l info 2>&1 | tee /var/log/salt_vault_initialize.log

echo "[appscript]: Vault's status"
vault status

echo "[appscript]: Completed appscript vault successfully!"
