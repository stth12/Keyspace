import { License, Prisma } from "@prisma/client";
import { v7 as uuid } from "uuid";
import { randomBytes } from "node:crypto";
import { db, transaction, Tx, audit, lockLicense, dbTime } from "./database";
import { config, keyStore, hmacKeys } from "./config";
import { Failure } from "./errors";
import {
  generateLicense,
  normalizeLicense,
  mac,
  hash,
  randomToken,
  canonical,
  signLP1,
  verifyLP1,
} from "../../../packages/crypto-server/src/index";
import {
  activateSchema,
  issueSchema,
  selfIssueSchema,
  scopeSchema,
  refreshSchema,
  patchSchema,
} from "../../../packages/contracts/src/index";
import { limit } from "./security";
import { revokeFamily } from "./auth";
const DAY = 86400000;
export function effective(l: License, now = Date.now()) {
  return l.status === "ACTIVE" && l.expiresAt && +l.expiresAt <= now
    ? "EXPIRED"
    : l.status;
}
export function licenseDto(
  l: License & {
    product?: { name: string; slug: string };
    owner?: { login: string };
    activations?: unknown[];
  },
) {
  return {
    id: l.id,
    user_id: l.userId,
    product_id: l.productId,
    product: l.product,
    owner: l.owner ? { login: l.owner.login } : undefined,
    masked_key: `LK1-${l.keyPrefix}-****-****-****-****-****-****-${l.keySuffix}`,
    status: effective(l),
    duration_seconds:
      l.durationSeconds === null ? null : Number(l.durationSeconds),
    is_lifetime: l.isLifetime,
    created_at: l.createdAt,
    activated_at: l.activatedAt,
    expires_at: l.expiresAt,
    max_devices: l.maxDevices,
    activation_count: l.activationCount,
    version: l.version,
    devices: l.activations,
  };
}
function allowed(
  l: NonNullable<Awaited<ReturnType<typeof lockLicense>>>,
  now: number,
) {
  if (!l.product.enabled || l.owner.status !== "ACTIVE")
    throw new Failure("INVALID_LICENSE", 403);
  const status = effective(l, now);
  if (status !== "ACTIVE" && status !== "NOT_ACTIVATED")
    throw new Failure("LICENSE_" + status, 403);
}
export async function issue(
  actor: string,
  input: unknown,
  admin: boolean,
  idempotency: string,
) {
  const b = issueSchema.parse(
    admin ? input : { ...selfIssueSchema.parse(input), max_devices: 1 },
  );
  const owner = admin ? ("user_id" in b ? b.user_id : undefined) : actor;
  if (!owner) throw new Failure("INVALID_REQUEST");
  const requestHash = hash(canonical(b)).toString("hex"),
    scope = actor + ":issue";
  return transaction(async (tx) => {
    await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${scope + idempotency},0))::text`;
    const previous = await tx.idempotency.findUnique({
      where: { scope_key: { scope, key: idempotency } },
    });
    if (previous) {
      if (previous.requestHash !== requestHash)
        throw new Failure("IDEMPOTENCY_CONFLICT", 409);
      const old = await tx.license.findUniqueOrThrow({
        where: { id: previous.resourceId },
      });
      return { license: licenseDto(old), key_recoverable: false };
    }
    await tx.$queryRaw`SELECT id FROM products WHERE id=${b.product_id}::uuid FOR SHARE`;
    await tx.$queryRaw`SELECT id FROM users WHERE id=${owner}::uuid FOR SHARE`;
    const p = await tx.product.findUnique({ where: { id: b.product_id } }),
      u = await tx.user.findUnique({ where: { id: owner } });
    if (!p?.enabled || u?.status !== "ACTIVE")
      throw new Failure("INVALID_PRODUCT", 400);
    let max = admin && "max_devices" in b ? b.max_devices : 1;
    if (!admin) {
      await tx.$queryRaw`SELECT id FROM license_entitlements WHERE "userId"=${actor}::uuid AND "productId"=${b.product_id}::uuid FOR UPDATE`;
      const e = await tx.entitlement.findUnique({
        where: { userId_productId: { userId: actor, productId: b.product_id } },
      });
      if (
        !e ||
        e.remaining < 1 ||
        (e.expiresAt && +e.expiresAt <= Date.now()) ||
        (b.is_lifetime
          ? !e.lifetime
          : !e.durations.includes(b.duration_seconds!))
      )
        throw new Failure("ISSUANCE_NOT_ALLOWED", 403);
      max = e.maxDevices;
      await tx.entitlement.update({
        where: { id: e.id },
        data: { remaining: { decrement: 1 } },
      });
    }
    const key = generateLicense(),
      normalized = normalizeLicense(key);
    const l = await tx.license.create({
      data: {
        id: uuid(),
        userId: owner,
        productId: b.product_id,
        keyHash: mac(config.hmac, normalized),
        hmacKeyId: config.hmacId,
        keyPrefix: normalized.slice(4, 8),
        keySuffix: normalized.slice(-4),
        durationSeconds:
          b.duration_seconds === null ? null : BigInt(b.duration_seconds),
        isLifetime: b.is_lifetime,
        maxDevices: max,
        createdBy: actor,
      },
    });
    await tx.idempotency.create({
      data: { scope, key: idempotency, requestHash, resourceId: l.id },
    });
    await audit(tx, actor, "LicenseCreated", "license", l.id, {
      reason: "reason" in b ? b.reason || "Self issuance" : "Self issuance",
    });
    return { license: licenseDto(l), license_key: key };
  });
}
async function activeSigningKey(
  tx: Tx,
  purpose: "application-session" | "offline-license",
) {
  const row = await tx.signingKey.findFirst({
    where: { purpose, status: "ACTIVE" },
  });
  const key = keyStore.keys.find(
    (k) => k.id === row?.id && k.purpose === purpose && k.status === "ACTIVE",
  );
  if (
    !key ||
    !row ||
    +row.notBefore > Date.now() ||
    +row.verifyUntil <= Date.now()
  )
    throw new Failure("SERVICE_UNAVAILABLE", 503);
  return key;
}
async function token(
  tx: Tx,
  s: {
    id: string;
    licenseId: string;
    userId: string;
    productId: string;
    deviceId: string;
    licenseVersion: number;
    absoluteExpiresAt: Date;
    idleExpiresAt: Date;
  },
  l: License,
  now: Date,
) {
  const key = await activeSigningKey(tx, "application-session");
  const issued = Math.floor(+now / 1000),
    end = Math.floor(
      Math.min(
        +now + 300000,
        +s.absoluteExpiresAt,
        +s.idleExpiresAt,
        l.expiresAt ? +l.expiresAt : Infinity,
        key.verifyUntil * 1000,
      ) / 1000,
    );
  if (end <= issued) throw new Failure("SESSION_EXPIRED", 401);
  return {
    token: signLP1(key, {
      issuer: config.issuer,
      audience: "application-api",
      session_id: s.id,
      license_id: s.licenseId,
      user_id: s.userId,
      product_id: s.productId,
      device_id: s.deviceId,
      issued_at: issued,
      expires_at: end,
      license_version: s.licenseVersion,
      nonce: randomBytes(16).toString("base64url"),
    }),
    expires_at: new Date(end * 1000),
  };
}
export async function activate(input: unknown) {
  const b = activateSchema.parse(input);
  let normalized: string;
  try {
    normalized = normalizeLicense(b.license_key);
  } catch {
    throw new Failure("INVALID_LICENSE", 401);
  }
  await limit("activate-key", normalized, 10, 300);
  await limit("activate-device", b.device_id, 20, 300);
  let found: License | null = null;
  for (const [id, key] of hmacKeys) {
    found = await db.license.findFirst({
      where: { hmacKeyId: id, keyHash: mac(key, normalized) },
    });
    if (found) break;
  }
  if (!found || found.productId !== b.product_id)
    throw new Failure("INVALID_LICENSE", 401);
  return transaction(async (tx) => {
    let l = await lockLicense(tx, found!.id);
    if (!l) throw new Failure("INVALID_LICENSE", 401);
    const now = await dbTime(tx);
    allowed(l, +now);
    let device = await tx.activation.findUnique({
      where: { licenseId_deviceId: { licenseId: l.id, deviceId: b.device_id } },
    });
    if (device?.revokedAt) throw new Failure("DEVICE_REVOKED", 403);
    if (!device) {
      const count = await tx.activation.count({
        where: { licenseId: l.id, revokedAt: null },
      });
      if (l.maxDevices !== null && count >= l.maxDevices)
        throw new Failure("DEVICE_LIMIT_REACHED", 403);
      device = await tx.activation.create({
        data: {
          id: uuid(),
          licenseId: l.id,
          deviceId: b.device_id,
          firstSeenAt: now,
          lastSeenAt: now,
        },
      });
      await tx.license.update({
        where: { id: l.id },
        data: { activationCount: { increment: 1 } },
      });
      await audit(tx, l.userId, "DeviceAdded", "license", l.id, {
        device_id: b.device_id,
      });
    }
    if (!l.activatedAt) {
      await tx.license.update({
        where: { id: l.id },
        data: {
          status: "ACTIVE",
          activatedAt: now,
          expiresAt: l.isLifetime
            ? null
            : new Date(+now + Number(l.durationSeconds) * 1000),
        },
      });
    }
    if (l.hmacKeyId !== config.hmacId)
      await tx.license.update({
        where: { id: l.id },
        data: {
          keyHash: mac(config.hmac, normalized),
          hmacKeyId: config.hmacId,
        },
      });
    l = await tx.license.findUniqueOrThrow({
      where: { id: l.id },
      include: { owner: true, product: true },
    });
    await tx.appSession.updateMany({
      where: { licenseId: l.id, deviceId: b.device_id, revokedAt: null },
      data: { revokedAt: now },
    });
    const absolute = new Date(
        Math.min(+now + 30 * DAY, l.expiresAt ? +l.expiresAt : Infinity),
      ),
      idle = new Date(Math.min(+absolute, +now + 7 * DAY));
    const s = await tx.appSession.create({
      data: {
        id: uuid(),
        licenseId: l.id,
        userId: l.userId,
        productId: l.productId,
        activationId: device.id,
        deviceId: b.device_id,
        licenseVersion: l.version,
        absoluteExpiresAt: absolute,
        idleExpiresAt: idle,
      },
    });
    const fresh = randomToken();
    await tx.refreshToken.create({
      data: {
        id: uuid(),
        tokenHash: hash(fresh),
        appSessionId: s.id,
        expiresAt: idle,
      },
    });
    const signed = await token(tx, s, l, now);
    await audit(tx, l.userId, "LicenseActivated", "license", l.id, {
      device_id: b.device_id,
      session_id: s.id,
    });
    return {
      success: true,
      user: { id: l.userId, login: l.owner.login },
      license: licenseDto(l),
      session: signed,
      refresh: { token: fresh, expires_at: idle },
      server_time: now,
    };
  });
}
export async function appContext(tx: Tx, raw: string, input: unknown) {
  const b = scopeSchema.parse(input);
  let p;
  try {
    p = verifyLP1(raw, keyStore.keys, "application-session", config.issuer);
  } catch {
    throw new Failure("INVALID_SESSION", 401);
  }
  if (
    !("session_id" in p) ||
    p.product_id !== b.product_id ||
    p.device_id !== b.device_id
  )
    throw new Failure("INVALID_SESSION", 401);
  const l = await lockLicense(tx, p.license_id);
  if (!l) throw new Failure("INVALID_SESSION", 401);
  const now = await dbTime(tx);
  allowed(l, +now);
  if (l.status !== "ACTIVE" || l.version !== p.license_version)
    throw new Failure("INVALID_SESSION", 401);
  const s = await tx.appSession.findUnique({
    where: { id: p.session_id },
    include: { activation: true },
  });
  const keyId = JSON.parse(
    Buffer.from(raw.split(".")[1], "base64url").toString(),
  ).key_id;
  const k = await tx.signingKey.findUnique({ where: { id: keyId } });
  if (
    !k ||
    k.status === "REVOKED" ||
    +k.verifyUntil <= +now ||
    !s ||
    s.revokedAt ||
    s.activation.revokedAt ||
    +s.absoluteExpiresAt <= +now ||
    +s.idleExpiresAt <= +now ||
    s.licenseVersion !== l.version ||
    s.licenseId !== l.id ||
    s.userId !== p.user_id ||
    s.productId !== b.product_id ||
    s.deviceId !== b.device_id
  )
    throw new Failure("INVALID_SESSION", 401);
  await limit("validate-session", s.id, 120, 60);
  await limit("validate-license", l.id, 300, 60);
  await limit("validate-device", s.deviceId, 180, 60);
  return { l, s, now };
}
export async function validate(raw: string, input: unknown) {
  return transaction(async (tx) => {
    const { l, s, now } = await appContext(tx, raw, input);
    if (+now - +s.lastSeenAt >= 60000) {
      await tx.appSession.update({
        where: { id: s.id },
        data: { lastSeenAt: now },
      });
      await tx.activation.update({
        where: { id: s.activationId },
        data: { lastSeenAt: now },
      });
    }
    return {
      success: true,
      user: { id: l.userId, login: l.owner.login },
      license: licenseDto(l),
      server_time: now,
      next_validation_after_seconds: 60,
    };
  });
}
export async function appRefresh(input: unknown) {
  const b = refreshSchema.parse(input);
  const r0 = await db.refreshToken.findUnique({
    where: { tokenHash: hash(b.refresh_token) },
    include: { appSession: true },
  });
  if (!r0?.appSession) throw new Failure("INVALID_SESSION", 401);
  const fresh = randomToken();
  const result = await transaction(async (tx) => {
    const l = await lockLicense(tx, r0.appSession!.licenseId);
    if (!l) throw new Failure("INVALID_SESSION", 401);
    await tx.$queryRaw`SELECT id FROM application_sessions WHERE id=${r0.appSessionId}::uuid FOR UPDATE`;
    const r = await tx.refreshToken.findUniqueOrThrow({ where: { id: r0.id } });
    const s = await tx.appSession.findUniqueOrThrow({
      where: { id: r0.appSessionId! },
      include: { activation: true },
    });
    if (s.productId !== b.product_id || s.deviceId !== b.device_id)
      throw new Failure("INVALID_SESSION", 401);
    if (r.consumedAt || r.revokedAt) {
      await revokeFamily(tx, s.id, "app");
      await audit(tx, s.userId, "RefreshReuse", "session", s.id);
      await tx.securityEvent.create({
        data: {
          id: uuid(),
          type: "REFRESH_REUSE",
          metadata: { session_id: s.id },
        },
      });
      return null;
    }
    const now = await dbTime(tx);
    allowed(l, +now);
    if (
      l.status !== "ACTIVE" ||
      s.revokedAt ||
      s.activation.revokedAt ||
      s.licenseVersion !== l.version ||
      +r.expiresAt <= +now ||
      +s.idleExpiresAt <= +now ||
      +s.absoluteExpiresAt <= +now
    )
      throw new Failure("INVALID_SESSION", 401);
    await limit("app-refresh", s.id, 10, 60);
    const idle = new Date(
      Math.min(
        +s.absoluteExpiresAt,
        +now + 7 * DAY,
        l.expiresAt ? +l.expiresAt : Infinity,
      ),
    );
    await tx.refreshToken.update({
      where: { id: r.id },
      data: { consumedAt: now },
    });
    await tx.refreshToken.create({
      data: {
        id: uuid(),
        parentId: r.id,
        tokenHash: hash(fresh),
        appSessionId: s.id,
        expiresAt: idle,
      },
    });
    const updated = await tx.appSession.update({
      where: { id: s.id },
      data: { idleExpiresAt: idle, lastSeenAt: now },
    });
    return {
      session: await token(tx, updated, l, now),
      refresh: { token: fresh, expires_at: idle },
      server_time: now,
    };
  });
  if (!result) throw new Failure("INVALID_SESSION", 401);
  return result;
}
export async function offline(raw: string, input: unknown) {
  return transaction(async (tx) => {
    const { l, s, now } = await appContext(tx, raw, input);
    if (!l.product.offlineEnabled) throw new Failure("OFFLINE_DISABLED", 403);
    await limit("offline", s.id, 6, 3600);
    const key = await activeSigningKey(tx, "offline-license");
    const issued = Math.floor(+now / 1000),
      end = Math.floor(
        Math.min(
          +now + Math.min(l.product.offlineGrace, 604800) * 1000,
          l.expiresAt ? +l.expiresAt : Infinity,
          key.verifyUntil * 1000,
        ) / 1000,
      );
    if (end <= issued) throw new Failure("LICENSE_EXPIRED", 403);
    const nonce = randomBytes(16).toString("base64url");
    const signed = signLP1(key, {
      version: 1,
      issuer: config.issuer,
      audience: "offline-license",
      license_id: l.id,
      user_id: l.userId,
      product_id: l.productId,
      device_id: s.deviceId,
      issued_at: issued,
      valid_until: end,
      license_expires_at: l.expiresAt ? Math.floor(+l.expiresAt / 1000) : null,
      lifetime: l.isLifetime,
      license_version: l.version,
      nonce,
    });
    await tx.tokenIssuance.create({
      data: {
        id: uuid(),
        licenseId: l.id,
        sessionId: s.id,
        keyId: key.id,
        nonce,
        issuedAt: now,
        validUntil: new Date(end * 1000),
      },
    });
    await audit(tx, l.userId, "OfflineIssued", "license", l.id);
    return {
      token: signed,
      valid_until: new Date(end * 1000),
      server_time: now,
    };
  });
}
export async function mutateLicense(
  actor: string,
  id: string,
  operation: string,
  input: unknown,
) {
  return transaction(async (tx) => {
    const l = await lockLicense(tx, id);
    if (!l) throw new Failure("NOT_FOUND", 404);
    const b = patchSchema.parse({
      ...(input as object),
      operation:
        operation === "patch"
          ? (input as { operation: string }).operation
          : "set_lifetime",
    });
    if (l.version !== b.expected_version)
      throw new Failure("VERSION_CONFLICT", 409);
    const now = await dbTime(tx),
      state = effective(l, +now);
    if (state === "REVOKED") throw new Failure("INVALID_TRANSITION", 409);
    let data: Prisma.LicenseUpdateInput = { version: { increment: 1 } };
    if (operation === "revoke")
      data = { ...data, status: "REVOKED", revokedAt: now, blockedAt: null };
    else if (operation === "block") {
      if (!["ACTIVE", "NOT_ACTIVATED"].includes(state))
        throw new Failure("INVALID_TRANSITION", 409);
      data = { ...data, status: "BLOCKED", blockedAt: now };
    } else if (operation === "unblock") {
      if (l.status !== "BLOCKED") throw new Failure("INVALID_TRANSITION", 409);
      data = {
        ...data,
        status: l.activatedAt
          ? l.expiresAt && +l.expiresAt <= +now
            ? "EXPIRED"
            : "ACTIVE"
          : "NOT_ACTIVATED",
        blockedAt: null,
      };
    } else {
      switch (b.operation) {
        case "set_unactivated_duration":
          if (l.activatedAt || !b.duration_seconds)
            throw new Failure("INVALID_TRANSITION", 409);
          data = {
            ...data,
            isLifetime: false,
            durationSeconds: BigInt(b.duration_seconds),
          };
          break;
        case "set_lifetime":
          data = {
            ...data,
            isLifetime: true,
            durationSeconds: null,
            expiresAt: null,
            status:
              l.status === "BLOCKED"
                ? "BLOCKED"
                : l.activatedAt
                  ? "ACTIVE"
                  : "NOT_ACTIVATED",
          };
          break;
        case "set_max_devices": {
          if (b.max_devices === undefined) throw new Failure("INVALID_REQUEST");
          const count = await tx.activation.count({
            where: { licenseId: id, revokedAt: null },
          });
          if (b.max_devices !== null && b.max_devices < count)
            throw new Failure("DEVICE_LIMIT_REACHED", 409);
          data.maxDevices = b.max_devices;
          break;
        }
        default: {
          if (!l.activatedAt) throw new Failure("INVALID_TRANSITION", 409);
          const expiry =
            b.operation === "extend_by_seconds"
              ? new Date(
                  Math.max(l.expiresAt ? +l.expiresAt : +now, +now) +
                    (b.duration_seconds || 0) * 1000,
                )
              : new Date(b.expires_at || "");
          const duration = Math.floor((+expiry - +l.activatedAt) / 1000);
          if (
            !Number.isFinite(+expiry) ||
            +expiry <= +now ||
            duration < 1 ||
            duration > 315360000
          )
            throw new Failure("INVALID_EXPIRATION");
          data = {
            ...data,
            isLifetime: false,
            durationSeconds: BigInt(duration),
            expiresAt: expiry,
            status: l.status === "BLOCKED" ? "BLOCKED" : "ACTIVE",
          };
        }
      }
    }
    const updated = await tx.license.update({ where: { id }, data });
    await tx.appSession.updateMany({
      where: { licenseId: id, revokedAt: null },
      data: { revokedAt: now },
    });
    await audit(
      tx,
      actor,
      operation === "patch" ? "ExpirationChanged" : "License" + operation,
      "license",
      id,
      {
        reason: b.reason,
        operation: operation === "patch" ? b.operation : operation,
      },
    );
    return licenseDto(updated);
  });
}
