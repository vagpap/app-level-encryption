# Local Development Workflow

## Purpose

This runbook defines the primary Docker-based local setup and the fallback workflow when Docker Compose is not available.

## Prerequisites

Run prerequisite checks:

```bash
bash scripts/check-prerequisites.sh
```

Expected tools:

- Docker with Compose plugin
- Java 21+
- Maven 3.9+

Ensure scripts are executable:

```bash
chmod +x scripts/*.sh db/tests/*.sh vault/tests/*.sh tests/*.sh
```

## Primary Workflow (Docker Compose)

1. Start local stack and run Vault bootstrap:

```bash
bash scripts/start-local.sh
```

1. Confirm services:

```bash
docker compose ps
```

1. Access endpoints:

- PostgreSQL: localhost:5432
- Vault: [http://localhost:8200](http://localhost:8200)
- API: [http://localhost:8080](http://localhost:8080) (when running app)

## Fallback Workflow (No Docker)

Use fallback only when Docker Compose cannot be used in the current environment.

1. Run API in in-memory mode:

```bash
bash scripts/start-local-fallback.sh
```

1. Validate API health:

```bash
curl http://localhost:8080/actuator/health
```

## Troubleshooting

1. Docker daemon not running:

- Start Docker Desktop or daemon service.
- Re-run `bash scripts/check-prerequisites.sh`.

1. Vault init fails:

- Check Vault container logs: docker compose logs vault
- Re-run bootstrap: docker compose run --rm vault-init

1. Port conflicts:

- Check listeners on 5432/8200/8080 and free conflicting processes.
- Override mapped ports in docker-compose.yml if needed.

1. Fallback startup fails:

- Verify Java and Maven paths.
- Run `mvn -q test` first to ensure project compiles.

## Exit and Cleanup

Stop and remove services:

```bash
docker compose down
```

Remove volumes if a clean reset is needed:

```bash
docker compose down -v
```
