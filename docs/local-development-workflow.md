# Local Development Workflow

## Purpose

This runbook defines the primary Docker-based local setup and the fallback workflow when Docker Compose is not available.

## Prerequisites

Expected tools:

- Docker with Compose plugin
- Java 21+
- Maven 3.9+

## Primary Workflow (Docker Compose)

1. Start local stack and run Vault bootstrap:

```bash
docker compose up -d postgres vault
```

2. Confirm services:

```bash
docker compose ps
```

3. Initialise vault:

```bash
docker compose run --rm vault-init
```

Check logs to get the AppRole `role-id` and generated `secret-id`. These are necessary environment variables (`VAULT_ROLE_ID` & `VAULT_SECRET_ID`) for the application to start.

1. Access endpoints:

- PostgreSQL: localhost:5432
- Vault: [http://localhost:8200](http://localhost:8200)
- API: [http://localhost:8080](http://localhost:8080) (when running app)

## Fallback Workflow (No Docker)

Use fallback only when Docker Compose cannot be used in the current environment.

1. Run API in in-memory mode:

```bash
mvn -q -DskipTests -Dspring-boot.run.profiles=inmemory spring-boot:run
```

2. Validate API health:

```bash
curl http://localhost:8080/actuator/health
```

## Exit and Cleanup

Stop and remove services:

```bash
docker compose down
```

Remove volumes if a clean reset is needed:

```bash
docker compose down -v
```
