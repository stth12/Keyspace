-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ADMIN');

-- CreateEnum
CREATE TYPE "AccountStatus" AS ENUM ('ACTIVE', 'BLOCKED');

-- CreateEnum
CREATE TYPE "LicenseStatus" AS ENUM ('NOT_ACTIVATED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'BLOCKED');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "login" VARCHAR(32) NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "status" "AccountStatus" NOT NULL DEFAULT 'ACTIVE',
    "authVersion" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "products" (
    "id" UUID NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "slug" VARCHAR(64) NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "offlineEnabled" BOOLEAN NOT NULL DEFAULT false,
    "offlineGrace" INTEGER NOT NULL DEFAULT 86400,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "products_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "license_entitlements" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "productId" UUID NOT NULL,
    "remaining" INTEGER NOT NULL,
    "durations" INTEGER[],
    "lifetime" BOOLEAN NOT NULL DEFAULT false,
    "maxDevices" INTEGER DEFAULT 1,
    "expiresAt" TIMESTAMPTZ(3),

    CONSTRAINT "license_entitlements_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "licenses" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "productId" UUID NOT NULL,
    "keyHash" BYTEA NOT NULL,
    "hmacKeyId" VARCHAR(64) NOT NULL,
    "keyPrefix" CHAR(4) NOT NULL,
    "keySuffix" CHAR(4) NOT NULL,
    "status" "LicenseStatus" NOT NULL DEFAULT 'NOT_ACTIVATED',
    "durationSeconds" BIGINT,
    "activatedAt" TIMESTAMPTZ(3),
    "expiresAt" TIMESTAMPTZ(3),
    "isLifetime" BOOLEAN NOT NULL DEFAULT false,
    "maxDevices" INTEGER DEFAULT 1,
    "activationCount" INTEGER NOT NULL DEFAULT 0,
    "createdBy" UUID NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,
    "revokedAt" TIMESTAMPTZ(3),
    "blockedAt" TIMESTAMPTZ(3),

    CONSTRAINT "licenses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "license_activations" (
    "id" UUID NOT NULL,
    "licenseId" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "firstSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "license_activations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "application_sessions" (
    "id" UUID NOT NULL,
    "licenseId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "productId" UUID NOT NULL,
    "activationId" UUID NOT NULL,
    "deviceId" UUID NOT NULL,
    "licenseVersion" INTEGER NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "absoluteExpiresAt" TIMESTAMPTZ(3) NOT NULL,
    "idleExpiresAt" TIMESTAMPTZ(3) NOT NULL,
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "application_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "web_sessions" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "authVersion" INTEGER NOT NULL,
    "csrfHash" BYTEA NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "absoluteExpiresAt" TIMESTAMPTZ(3) NOT NULL,
    "idleExpiresAt" TIMESTAMPTZ(3) NOT NULL,
    "mfaAt" TIMESTAMPTZ(3),
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "web_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "refresh_tokens" (
    "id" UUID NOT NULL,
    "tokenHash" BYTEA NOT NULL,
    "webSessionId" UUID,
    "appSessionId" UUID,
    "parentId" UUID,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    "consumedAt" TIMESTAMPTZ(3),
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" UUID NOT NULL,
    "actorUserId" UUID,
    "action" VARCHAR(80) NOT NULL,
    "targetType" VARCHAR(40) NOT NULL,
    "targetId" TEXT,
    "metadata" JSONB NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_events" (
    "id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "metadata" JSONB NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "outbox_events" (
    "id" UUID NOT NULL,
    "auditId" UUID NOT NULL,
    "payload" JSONB NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deliveredAt" TIMESTAMPTZ(3),
    "attempts" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "signing_keys" (
    "id" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "notBefore" TIMESTAMPTZ(3) NOT NULL,
    "verifyUntil" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "signing_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "token_issuances" (
    "id" UUID NOT NULL,
    "licenseId" UUID NOT NULL,
    "sessionId" UUID NOT NULL,
    "keyId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "issuedAt" TIMESTAMPTZ(3) NOT NULL,
    "validUntil" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "token_issuances_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "idempotency_records" (
    "scope" TEXT NOT NULL,
    "key" UUID NOT NULL,
    "requestHash" TEXT NOT NULL,
    "resourceId" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "idempotency_records_pkey" PRIMARY KEY ("scope","key")
);

-- CreateTable
CREATE TABLE "webauthn_credentials" (
    "id" TEXT NOT NULL,
    "userId" UUID NOT NULL,
    "publicKey" BYTEA NOT NULL,
    "counter" BIGINT NOT NULL,
    "transports" TEXT[],
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webauthn_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_login_key" ON "users"("login");

-- CreateIndex
CREATE INDEX "users_status_createdAt_id_idx" ON "users"("status", "createdAt", "id");

-- CreateIndex
CREATE UNIQUE INDEX "products_slug_key" ON "products"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "license_entitlements_userId_productId_key" ON "license_entitlements"("userId", "productId");

-- CreateIndex
CREATE UNIQUE INDEX "licenses_keyHash_key" ON "licenses"("keyHash");

-- CreateIndex
CREATE INDEX "licenses_userId_createdAt_id_idx" ON "licenses"("userId", "createdAt", "id");

-- CreateIndex
CREATE INDEX "licenses_productId_status_expiresAt_idx" ON "licenses"("productId", "status", "expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "licenses_id_userId_productId_key" ON "licenses"("id", "userId", "productId");

-- CreateIndex
CREATE UNIQUE INDEX "license_activations_licenseId_deviceId_key" ON "license_activations"("licenseId", "deviceId");

-- CreateIndex
CREATE UNIQUE INDEX "license_activations_id_licenseId_deviceId_key" ON "license_activations"("id", "licenseId", "deviceId");

-- CreateIndex
CREATE INDEX "application_sessions_licenseId_revokedAt_idx" ON "application_sessions"("licenseId", "revokedAt");

-- CreateIndex
CREATE UNIQUE INDEX "refresh_tokens_tokenHash_key" ON "refresh_tokens"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "refresh_tokens_parentId_key" ON "refresh_tokens"("parentId");

-- CreateIndex
CREATE INDEX "refresh_tokens_expiresAt_idx" ON "refresh_tokens"("expiresAt");

-- CreateIndex
CREATE INDEX "audit_logs_createdAt_id_idx" ON "audit_logs"("createdAt", "id");

-- CreateIndex
CREATE INDEX "audit_logs_actorUserId_createdAt_idx" ON "audit_logs"("actorUserId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_events_auditId_key" ON "outbox_events"("auditId");

-- CreateIndex
CREATE UNIQUE INDEX "token_issuances_nonce_key" ON "token_issuances"("nonce");

-- AddForeignKey
ALTER TABLE "license_entitlements" ADD CONSTRAINT "license_entitlements_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "license_entitlements" ADD CONSTRAINT "license_entitlements_productId_fkey" FOREIGN KEY ("productId") REFERENCES "products"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_productId_fkey" FOREIGN KEY ("productId") REFERENCES "products"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "license_activations" ADD CONSTRAINT "license_activations_licenseId_fkey" FOREIGN KEY ("licenseId") REFERENCES "licenses"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "application_sessions" ADD CONSTRAINT "application_sessions_licenseId_userId_productId_fkey" FOREIGN KEY ("licenseId", "userId", "productId") REFERENCES "licenses"("id", "userId", "productId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "application_sessions" ADD CONSTRAINT "application_sessions_activationId_licenseId_deviceId_fkey" FOREIGN KEY ("activationId", "licenseId", "deviceId") REFERENCES "license_activations"("id", "licenseId", "deviceId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "web_sessions" ADD CONSTRAINT "web_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_webSessionId_fkey" FOREIGN KEY ("webSessionId") REFERENCES "web_sessions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_appSessionId_fkey" FOREIGN KEY ("appSessionId") REFERENCES "application_sessions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "refresh_tokens"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webauthn_credentials" ADD CONSTRAINT "webauthn_credentials_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
