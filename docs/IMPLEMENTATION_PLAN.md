# План реализации OnlineKeyGen

Архитектурная база: [ARCHITECTURE.md](ARCHITECTURE.md). На 2026-09-18 реализованы API, web, Tauri-клиент, база, LP1/LK1, миграции, тесты и Docker. Фазы 1–16 имеют работающую реализацию; 17–18 подготовлены и проверены локально, но требуют production-проверок ниже. Подробные результаты: [VERIFICATION.md](VERIFICATION.md).

Перед каждым этапом: проверить существующие файлы и инструкции; перечислить затрагиваемые пути; менять единственный доменный implementation; обновить contracts, OpenAPI, migrations и содержательные tests. Полный код созданных файлов предоставляется без placeholders; секреты генерируются отдельно и никогда не включаются в ответ.

| Phase | Результат | Главные затрагиваемые пути | Критерий завершения |
|---|---|---|---|
| 1 | Monorepo + infrastructure | package.json, config, apps/*, infra/*, compose | Установка по lockfile, typecheck/build, dev services healthy |
| 2 | PostgreSQL + Prisma | apps/api/prisma/* | Миграции на чистой БД, constraints/grants tests |
| 3 | Authentication | api/modules/auth, sessions, web/auth | Argon2, cookies/CSRF, refresh rotation/reuse, logout tests |
| 4 | RBAC | api/modules/rbac, guards, WebAuthn | USER denied ADMIN, ownership, bootstrap ADMIN и MFA |
| 5 | License generation | api/modules/licenses, contracts | CSPRNG, quota/idempotency, key once, audit |
| 6 | HMAC lookup | packages/crypto-server, license repository | Canonical LK1, versioned keys, migration on presentation |
| 7 | Activation | licenses/devices, migrations | First-use expiry и concurrent device limit tests |
| 8 | Application sessions | sessions, contracts | DB-backed sessions, separate refresh, full validation |
| 9 | Ed25519 | signing, lp1-spec, verifier | LP1 vectors, key purposes, manifest и rotation |
| 10 | Offline | offline, product policies | Grace bound, lifetime bound, explicit-denial behavior |
| 11 | User Dashboard | apps/web/app/dashboard, UI | Profile/licenses/self-issue, safe one-time key display |
| 12 | Admin Dashboard | web/admin, API/admin | Users/licenses/actions/stats/audit, pagination and MFA |
| 13 | Desktop | apps/desktop, Rust verifier | Tauri Windows build, storage, online/offline flows |
| 14 | Audit + security events | audit, security-events, worker | Transactional outbox, append-only grants, redaction |
| 15 | Rate limiting | rate-limit, Redis, edge | Multi-dimension atomic limits, fail-closed tests |
| 16 | Testing | all tests, CI | Полная integration/API/authz/concurrency/crypto матрица |
| 17 | Hardening | headers, parsers, deployment, runbooks | Secret/dependency scan, fuzz limits, incident drill |
| 18 | Production deployment | Dockerfiles, production compose, runbooks | TLS/secrets configured, restore tested, smoke tests |

Важная зависимость: порядок фаз не означает, что открытые auth/activation endpoints можно публиковать без audit/rate limiting. Минимальные audit и rate-limit hooks нужны уже в фазах 3–7; фазы 14–15 завершают aggregation/alerts/операционную настройку. Фаза 8 до 9 не выдаёт неподписанный самодельный token: сначала внедряется интерфейс signer, а публичный session flow включается только с полноценной фазой 9.

Текущее окружение: Node 24, PostgreSQL 17 и Redis 7 работают локально; полный стек через Caddy доступен на localhost:8080. Проверены 28 серверных тестов, 5 Rust-тестов, сборки, восстановление резервной копии и интерфейс в браузере.

Фактические модули компактнее первоначальных имён в таблице: доменная реализация находится в `apps/api/src/{auth,licenses,mfa,security,database,controller}.ts`, схема — `apps/api/prisma/schema.prisma`, web — `apps/web/app`, desktop — `apps/desktop/src-tauri`. Вторых реализаций этих модулей нет.

Незавершённые production-критерии: реальный домен/HTTPS, отдельные production-секреты, внешний immutable audit sink и мониторинг, независимое security review, нагрузочные и отказоустойчивые испытания, измеренный RPO/RTO, подписанный release installer и тест установки на чистой Windows VM. Linux/macOS desktop не квалифицированы; RustSec сообщает предупреждения, перечисленные в отчёте. Фазы 17–18 нельзя считать завершённым публичным production-развёртыванием.

Git сообщает об отличающемся владельце каталога. Read-only проверка выполнена с process-local `-c safe.directory=...`; глобальная Git-конфигурация не изменялась.
