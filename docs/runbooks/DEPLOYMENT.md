# Deployment / recovery

## Production first deployment

Use a separate host/DB/secret store from development. Generate fresh 32-byte keys, Ed25519 key pairs and a manifest root offline. The environment contract is `.env.example`; all secrets are 64 lowercase hex characters where symmetric. `KEYSTORE_FILE` points to the server-only key store. Never copy local admin credentials to production.

Set DOMAIN, WEB_ORIGIN=https://DOMAIN, API_ISSUER=https://DOMAIN, RP_ID=DOMAIN and AUDIT_SINK_URL to an authenticated HTTPS append-only receiver. Set AUDIT_SINK_TOKEN if required. The sink must deduplicate by Idempotency-Key and retain immutable copies. Manifest issuer must match API_ISSUER; regenerate and sign it with `scripts/rotate-keys.ts manifest` before serving a different issuer.

```sh
docker compose -f docker-compose.production.yml build
docker compose -f docker-compose.production.yml up -d --wait postgres redis
docker compose -f docker-compose.production.yml --profile ops run --rm migrate
docker compose -f docker-compose.production.yml --profile ops run --rm migrate npx tsx scripts/provision.ts
docker compose -f docker-compose.production.yml up -d backend frontend worker reverse-proxy
```

Only Caddy exposes ports. Point DNS to the host and open TCP 80/443 (UDP 443 optional). Verify HTTPS before setting HSTS policies for additional subdomains. Pin approved image digests in your deployment inventory after scanning; tags in source compose identify compatible families, not immutable releases.

Create the production administrator through the operator CLI with production runtime credentials. Do not grant the runtime user DDL or signing-key mutations. The migration role has stronger privileges and must not be mounted into ordinary containers; remove unused migration credentials from runtime env files. Use separate backend and migration env files or a secret manager in hardened installations.

Runtime health: `/api/v1/health/live`, `/api/v1/health/ready`. DB or Redis outage is fail-closed. Never replace DB validation with signature-only online access during an incident.

## Signing-key rotation

Operator host only, with root signing key available outside backend container:

```sh
npx tsx scripts/rotate-keys.ts rotate application-session
npx tsx scripts/rotate-keys.ts rotate offline-license
npx tsx scripts/rotate-keys.ts revoke OLD_KEY_ID
```

The file adapter requires API restart after rotation. New tokens fail closed if DB metadata and loaded key store disagree. Distribute the signed manifest before normal activation where uninterrupted offline clients matter. Revocation cannot reach disconnected clients. A revoked session key causes online failure even if a token's Ed25519 signature remains mathematically valid.

HMAC: put a new hex secret in LICENSE_HMAC_SECRET and new ID in LICENSE_HMAC_ACTIVE_KEY_ID; move old ID/secret into LICENSE_HMAC_PREVIOUS_JSON. There are at most four retained keys. Presentation of a valid old key migrates its HMAC. To remove old secrets, explicitly revoke/reissue remaining licenses; an offline database-only transformation is impossible.

JWT secret compromise: rotate JWT_ACCESS_SECRET and revoke all web_sessions/refresh families. Current adapter intentionally invalidates existing web access on rotation rather than maintaining a secret overlap. Clients log in again.

## Backup and restore

Schedule PostgreSQL full backups plus WAL archiving in the hosting environment, encrypted with a separate backup key. Capture key-store versions and restore procedures separately. Redis is not the source of licensing truth; restoring old Redis state must never restore revoked database sessions.

Example operator backup writes a custom-format dump inside the DB container, then copies it to an encrypted backup destination:

```sh
docker compose -f docker-compose.production.yml exec -T postgres pg_dump -U postgres -d licensing -Fc -f /tmp/licensing.dump
docker compose -f docker-compose.production.yml cp postgres:/tmp/licensing.dump ./licensing.dump
```

Restore into a NEW isolated database using pg_restore, apply current migrations and provision grants, then run integrity/security tests before switching traffic. Never test restore by replacing the live database. After a rollback in time, revoke sessions/refresh tokens and review licenses issued after the restore point. Recovery objectives in architecture are targets until measured with real backups.

## Desktop release

Generate public config for HTTPS issuer and correct product. Ship only the root PUBLIC key. Build NSIS using Tauri, sign the installer with the organisation's Windows code-signing certificate, and verify installation on a clean VM with WebView2. No updater is enabled until an independently protected updater signing key and release channel are configured. Never enable unsigned remote updates.

## Security release gate

Pass unit/API/integration/concurrency tests; run npm and Rust advisory scans; review openapi.json and CSP; scan client bundle and Git for secrets; exercise restore and signing-key compromise; confirm admin WebAuthn and runtime audit grants. Independent protocol review and load/availability qualification remain deployment responsibilities; this repository is not a third-party security certification.
