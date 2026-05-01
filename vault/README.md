# Vault Bootstrap

This folder contains the Vault bootstrap assets for IMP-002.

## Files

- `init.sh`: idempotent bootstrap script for engines, keys, secrets, policy, and AppRole.
- `policies/myapp-policy.hcl`: least-privilege policy for encryption service runtime.
- `tests/init-script-unit.sh`: static unit-style checks for script compliance.

## Usage

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=<root-or-bootstrap-token>
sh vault/init.sh
```

Unit-style validation:

```bash
bash vault/tests/init-script-unit.sh
```

Optional variables:

- `DB_USERNAME` (default `app_user`)
- `DB_PASSWORD` (default `change-me`)
- `GENERATE_SECRET_ID` (`true` by default)
