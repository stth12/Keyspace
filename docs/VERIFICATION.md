# Проверка реализации — 2026-09-18

Реализован локально запускаемый monorepo: Next.js, NestJS, PostgreSQL/Prisma, Redis, Caddy, Tauri. Это отчёт о выполненных проверках, а не независимая сертификация безопасности.

## Подтверждённые результаты

| Проверка | Результат |
|---|---|
| `npm run typecheck` | API/shared/web: успешно |
| `npm test` | 28 тестов: успешно, реальная PostgreSQL и Redis |
| `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml` | 5 тестов: успешно |
| `npm run build` | NestJS, Next.js production, Vite desktop: успешно |
| `npm run openapi` | Сформирован `docs/api/openapi.json` |
| Docker API и frontend | Linux-образы собраны и запущены |
| Caddy production configuration | `caddy validate`: valid configuration |
| HTTP smoke через Caddy | `/` и `/api/v1/health/ready`: 200, CSP присутствует |
| Браузер | Вход, кабинет, разрешённые варианты самостоятельной выдачи, одноразовое отображение ключа; кабинет проверен также через Docker на :8080 |
| Windows installer | Собран `apps/desktop/src-tauri/target/debug/bundle/nsis/Keyspace_1.0.0_x64-setup.exe` |
| Backup/restore | pg_dump → отдельная временная БД → pg_restore; совпали количества users/licenses/audit_logs и constraints; тестовая БД удалена |
| npm audit | 0 известных уязвимостей |
| cargo audit | 0 записей vulnerability; 7 предупреждений, разобраны ниже |
| Проверка клиентских assets | В 14 assets не обнаружены значения настроенных server secrets и маркеры private keys |

Тесты покрывают HMAC-векторы, LK1, подделку LP1, назначение/issuer/срок подписи, ChaCha AEAD tampering, USER→ADMIN запрет, чужую лицензию, mass assignment, CSRF, квоты, idempotency, неизменность первой активации, истечение, Lifetime offline bound, blocked/revoked license, revoked device, disabled product, refresh reuse, WebAuthn с настоящей подписью P-256, append-only grants, Redis limits, malformed/oversized JSON. Конкурентная проверка запускает 50 активаций одной лицензии: ровно одно устройство получает доступ; квота самостоятельной выдачи проверяется 20 конкурентными запросами. Rust проверяет Node-generated LP1, изменение подписи, expiry, rollback манифеста и локального времени.

## Предупреждения RustSec

Полный Cargo.lock содержит зависимости для нескольких платформ. `cargo tree --target x86_64-pc-windows-msvc` подтвердил отсутствие `glib` и `proc-macro-error` в Windows-графе.

| Advisory | Пакет | Решение |
|---|---|---|
| RUSTSEC-2024-0429 | glib 0.18.5, unsound VariantStrIter | Linux desktop не выпускать до обновления upstream GTK/Tauri chain или отдельного документированного анализа достижимости |
| RUSTSEC-2024-0370 | proc-macro-error 1.0.4, unmaintained | Не входит в текущий Windows target; отслеживать upstream |
| RUSTSEC-2025-0081 | unic-char-property 0.9.0 | Входит через Tauri/urlpattern; предупреждение о сопровождении, требуется мониторинг upstream |
| RUSTSEC-2025-0075 | unic-char-range 0.9.0 | То же |
| RUSTSEC-2025-0080 | unic-common 0.9.0 | То же |
| RUSTSEC-2025-0100 | unic-ucd-ident 0.9.0 | То же |
| RUSTSEC-2025-0098 | unic-ucd-version 0.9.0 | То же |

Предупреждения не подавлены через ignore-файл. Успешный exit code cargo audit не означает отсутствие предупреждений.

## Что ещё необходимо перед публичным запуском

1. Настроить домен, отдельный сервер, DNS/TLS и свежие production secrets. Не переносить development-администратора, fixtures или `.env` в production.
2. Подключить внешний append-only audit sink, алерты, резервное копирование с WAL и проверить RPO/RTO на целевой инфраструктуре. Локальный JSONL export не является immutable хранилищем.
3. Подписать release installer сертификатом издателя и выполнить установку/обновление на чистой Windows VM. Собранный сейчас installer — development/debug для localhost; native UI и системное хранилище не прошли автоматизированный end-to-end тест на чистой машине.
4. Провести независимый review LP1/авторизации и нагрузочные/аварийные испытания. Docker Compose здесь — один сервер, не HA.
5. При интеграции другого приложения ограничить его серверные функции проверенной application session. Модифицированный клиент может убрать локальную проверку и запускать полностью локальный функционал; протокол не делает враждебный компьютер доверенным.
6. Offline revoke вступает в силу после reconnect или истечения proof. Snapshot rollback и извлечение данных владельцем машины остаются рисками. ChaCha не используется для сокрытия offline payload от самого владельца клиента.
7. File signer требует контролируемого рестарта при ротации. KMS/Vault, zero-downtime rollout ключей и автоматизированная долгосрочная retention policy требуют дальнейшей операционной интеграции.

## Запуск и исходники

- Полный локальный стек: `docker compose --profile full up -d --build`, затем http://localhost:8080.
- Альтернатива для разработки: `./scripts/start-local.ps1`, затем http://localhost:3000.
- Инструкции: [README](../README.md), [deployment runbook](runbooks/DEPLOYMENT.md).
- Архитектура и threat model: [ARCHITECTURE.md](ARCHITECTURE.md).
- Полный код с путями файлов: [SOURCE_BUNDLE.md](SOURCE_BUNDLE.md). Секреты исключены.
- Администратор `administrator`: случайный локальный пароль находится только в `.secrets/admin-bootstrap.json`. Просроченный MFA bootstrap обновляется командой `npm run admin -- mfa-bootstrap administrator`. Для работы админ-панели требуется WebAuthn.
