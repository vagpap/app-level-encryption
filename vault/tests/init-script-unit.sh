#!/usr/bin/env bash
set -euo pipefail

# Unit-style validation for vault/init.sh static compliance.
# Run: bash vault/tests/init-script-unit.sh

script_path="vault/init.sh"
if [ ! -f "$script_path" ]; then
  echo "Missing file: $script_path"
  exit 1
fi

content="$(cat "$script_path")"

required_patterns=(
  'vault secrets enable -path="\$\{MOUNT_PATH\}" "\$\{ENGINE_TYPE\}"'
  'enable_engine_if_missing "\$\{TRANSIT_MOUNT\}" "transit"'
  'enable_engine_if_missing "\$\{KV_MOUNT\}" "kv-v2"'
  'vault write "\$\{TRANSIT_MOUNT\}/keys/\$\{KEK_NAME\}" type="aes256-gcm96"'
  'vault kv put "\$\{BIK_PATH\}" key="\$\{BIK_VALUE\}"'
  'vault kv put "\$\{DB_PATH\}" username="\$\{DB_USERNAME\}" password="\$\{DB_PASSWORD\}"'
  'vault policy write "\$\{POLICY_NAME\}" "\$\{POLICY_FILE\}"'
  'vault write "auth/approle/role/\$\{APPROLE_NAME\}"'
  'secret_id_num_uses="0"'
  'secret_id_ttl="0"'
)

for pattern in "${required_patterns[@]}"; do
  if ! grep -Eq "$pattern" <<<"$content"; then
    echo "Missing required pattern in init.sh: $pattern"
    exit 1
  fi
done

echo "vault/init.sh static unit checks passed"
