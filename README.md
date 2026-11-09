# Keyspace / OnlineKeyGen

Monorepo: Next.js web + NestJS API + PostgreSQL/Prisma + Redis + Tauri desktop. License keys LK1, signed session/offline tokens LP1. Security design: [architecture](docs/ARCHITECTURE.md); implementation deviations: [ADRs](docs/adr/0002-implementation-decisions.md).

## Local setup (Node 24, Docker, Rust for desktop)

```powershell
npm ci
npm run setup:dev
docker compose up -d --wait postgres redis
npm run db:generate
npm run db:migrate
npx tsx scripts/provision.ts
npm run admin -- create administrator
npm run admin -- product keyspace "Keyspace Desktop" --offline
npx tsx scripts/desktop-config.ts
```

`setup:dev` refuses to overwrite existing secrets. Local PostgreSQL is bound to 127.0.0.1:15432; Redis to 127.0.0.1:56379. Keep `.env` and `.secrets/` private. Admin password and 15-minute WebAuthn enrollment code are saved to `.secrets/admin-bootstrap.json`, never printed to logs. Renew enrollment code with `npm run admin -- mfa-bootstrap administrator` if needed. No fixed default password.

On Windows, `./scripts/start-local.ps1` starts API, web and worker in the background. Alternatively run separate terminals:

```powershell
npm run dev:api
npm run dev:web
npm run worker
```

Web: http://localhost:3000. API: http://localhost:4000/api/v1. Development Swagger: http://localhost:4000/api/docs.

Create a user in the web UI. Sign in as administrator, enroll a WebAuthn authenticator using the bootstrap file, and verify MFA. Then issue a license for that user's UUID or grant self-issuance quota. Regular registration never grants issuance rights. API license keys are shown only once.

Desktop development:

```powershell
npm run tauri -w @lk/desktop -- dev
```

Client config is public: `apps/desktop/src-tauri/client-config.json`. Change product ID/issuer/root public key for your deployment. Release builds refuse HTTP at startup. Windows Credential Manager stores session credentials; no server secrets are embedded. Offline is optional, bounded, and cannot stop a modified executable or restore of a full VM snapshot.

## Verification

Full local Docker stack: `docker compose --profile full up -d --build`. Open http://localhost:8080. The database must first be migrated and provisioned using the setup commands above. This local mode uses HTTP and development cookies; it must not be exposed publicly.

```powershell
npm run typecheck
npm test
npm run build
npm run openapi
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml
npm audit
cargo audit --file apps/desktop/src-tauri/Cargo.lock
node scripts/verify-client-secrets.mjs
```

Integration tests require the local database and Redis; use a separate test environment for CI. They create randomly named fixture users/products; never run them against production. Tests intentionally exercise DB constraints and append-only audit. Runtime role must be provisioned after migrations.

## Deployment and operations

See [deployment runbook](docs/runbooks/DEPLOYMENT.md). Production is not obtained by merely setting NODE_ENV: configure real DNS/TLS, separate secrets, MFA, external audit sink, backup/restore, alerts and signed desktop distribution. Docker Compose is a single-host deployment, not HA.

Full source files are in the repository. `node scripts/source-bundle.mjs` creates `docs/SOURCE_BUNDLE.md` with complete paths and contents, excluding secrets, lockfiles and generated output.

Latest execution results and release limitations: [verification report](docs/VERIFICATION.md). Local backup/restore check: `./scripts/verify-restore.ps1` (stop writers for a consistent count comparison).
# Интерактивная production-установка

На Ubuntu Server 22.04/24.04 из отдельной чистой копии проекта:

```sh
sudo python3 scripts/install-production.py
```

Установщик запросит домен, настройки администратора, продукта и внешнего аудита,
подготовит секреты и запустит Docker-сервисы. Повторный запуск продолжает установку
без сброса данных. Требования, ограничения и действия после запуска:
[инструкция установщика](docs/runbooks/INSTALLER_RU.md).
