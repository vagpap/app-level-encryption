#!/usr/bin/env sh
set -eu

# Idempotent Vault bootstrap for local and CI environments.
# Requires: VAULT_ADDR, VAULT_TOKEN, vault CLI

if ! command -v vault >/dev/null 2>&1; then
  echo "vault CLI is required but not installed" >&2
  exit 1
fi

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"

POLICY_NAME="myapp-policy"
APPROLE_NAME="myapp-role"
TRANSIT_MOUNT="transit"
KV_MOUNT="secret"
KEK_NAME="app-kek"
BIK_PATH="${KV_MOUNT}/myapp/bik"
DB_PATH="${KV_MOUNT}/myapp/db"
POLICY_FILE="$(dirname "$0")/policies/${POLICY_NAME}.hcl"

DB_USERNAME="${DB_USERNAME:-app_user}"
DB_PASSWORD="${DB_PASSWORD:-change-me}"

log() {
  echo "[vault-init] $1"
}

enable_engine_if_missing() {
  MOUNT_PATH="$1"
  ENGINE_TYPE="$2"

  if vault secrets list | grep -q "^${MOUNT_PATH}/"; then
    log "Secrets engine '${MOUNT_PATH}' already enabled"
  else
    log "Enabling secrets engine '${MOUNT_PATH}' (${ENGINE_TYPE})"
    vault secrets enable -path="${MOUNT_PATH}" "${ENGINE_TYPE}"
  fi
}

ensure_transit_key() {
  if vault read "${TRANSIT_MOUNT}/keys/${KEK_NAME}" >/dev/null 2>&1; then
    log "Transit key '${KEK_NAME}' already exists"
  else
    log "Creating transit key '${KEK_NAME}'"
    vault write "${TRANSIT_MOUNT}/keys/${KEK_NAME}" type="aes256-gcm96" >/dev/null
  fi
}

ensure_bik_secret() {
  if vault kv get "${BIK_PATH}" >/dev/null 2>&1; then
    log "BIK secret already exists at '${BIK_PATH}'"
  else
    log "Generating and storing BIK secret at '${BIK_PATH}'"
    BIK_VALUE="$(vault write -field=random_bytes sys/tools/random bytes=32 format=base64)"
    vault kv put "${BIK_PATH}" key="${BIK_VALUE}" >/dev/null
  fi
}

ensure_db_secret() {
  if vault kv get "${DB_PATH}" >/dev/null 2>&1; then
    log "DB secret already exists at '${DB_PATH}'"
  else
    log "Writing initial DB secret at '${DB_PATH}'"
    vault kv put "${DB_PATH}" username="${DB_USERNAME}" password="${DB_PASSWORD}" >/dev/null
  fi
}

ensure_policy() {
  if [ ! -f "${POLICY_FILE}" ]; then
    echo "Policy file not found: ${POLICY_FILE}" >&2
    exit 1
  fi

  log "Applying policy '${POLICY_NAME}'"
  vault policy write "${POLICY_NAME}" "${POLICY_FILE}" >/dev/null
}

ensure_approle() {
  log "Configuring AppRole '${APPROLE_NAME}'"
  vault auth enable approle >/dev/null 2>&1 || true

  vault write "auth/approle/role/${APPROLE_NAME}" \
    token_policies="${POLICY_NAME}" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    secret_id_ttl="0" \
    secret_id_num_uses="0" >/dev/null

  ROLE_ID="$(vault read -field=role_id auth/approle/role/${APPROLE_NAME}/role-id)"
  log "AppRole role_id: ${ROLE_ID}"

  if [ "${GENERATE_SECRET_ID:-true}" = "true" ]; then
    SECRET_ID="$(vault write -field=secret_id -f auth/approle/role/${APPROLE_NAME}/secret-id)"
    log "Generated secret_id for '${APPROLE_NAME}': ${SECRET_ID}"
  fi
}

main() {
  log "Starting Vault bootstrap"
  enable_engine_if_missing "${TRANSIT_MOUNT}" "transit"
  enable_engine_if_missing "${KV_MOUNT}" "kv-v2"
  ensure_transit_key
  ensure_bik_secret
  ensure_db_secret
  ensure_policy
  ensure_approle
  log "Vault bootstrap completed"
}

main
