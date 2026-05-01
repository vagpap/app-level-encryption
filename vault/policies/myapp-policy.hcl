path "transit/encrypt/app-kek" {
  capabilities = ["update"]
}

path "transit/decrypt/app-kek" {
  capabilities = ["update"]
}

path "transit/rewrap/app-kek" {
  capabilities = ["update"]
}

path "transit/keys/app-kek" {
  capabilities = ["read"]
}

path "secret/data/myapp/bik" {
  capabilities = ["read"]
}

path "secret/data/myapp/db" {
  capabilities = ["read"]
}

path "secret/metadata/myapp/bik" {
  capabilities = ["read"]
}

path "secret/metadata/myapp/db" {
  capabilities = ["read"]
}
