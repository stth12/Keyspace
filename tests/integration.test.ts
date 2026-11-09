import "dotenv/config";
import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { v7 as uuid } from "uuid";
import supertest from "supertest";
import { db, transaction, audit } from "../apps/api/src/database";
import { redis, limit } from "../apps/api/src/security";
import { config } from "../apps/api/src/config";
import { createApp } from "../apps/api/src/app";
import { passwordHash } from "../apps/api/src/auth";
import {
  issue,
  activate,
  validate,
  appRefresh,
  offline,
  mutateLicense,
} from "../apps/api/src/licenses";
import type { INestApplication } from "@nestjs/common";
import {
  generateKeyPairSync,
  randomBytes,
  createHash,
  sign,
} from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { mac, normalizeLicense } from "../packages/crypto-server/src/index";
let app: INestApplication,
  server: any,
  userId: string,
  otherId: string,
  productId: string;
const pass = "integration-test-password-93849",
  run = Date.now().toString(36);
let csrf: string;
let agent: ReturnType<typeof supertest.agent>;
async function createLicense(extra: object = {}) {
  return issue(
    userId,
    {
      user_id: userId,
      product_id: productId,
      duration_seconds: 3600,
      is_lifetime: false,
      max_devices: 1,
      reason: "Integration fixture",
      ...extra,
    },
    true,
    uuid(),
  );
}
beforeAll(async () => {
  await redis.ping();
  userId = uuid();
  otherId = uuid();
  productId = uuid();
  const ph = await passwordHash(pass);
  await db.user.createMany({
    data: [
      { id: userId, login: "test_" + run, passwordHash: ph },
      { id: otherId, login: "other_" + run, passwordHash: ph },
    ],
  });
  await db.product.create({
    data: {
      id: productId,
      name: "Test " + run,
      slug: "test-" + run,
      offlineEnabled: true,
    },
  });
  const result = await createApp();
  app = result.app;
  await app.init();
  server = app.getHttpServer();
  agent = supertest.agent(server);
  const login = await agent
    .post("/api/v1/auth/login")
    .set("Origin", config.origin)
    .send({ login: "test_" + run, password: pass });
  expect(login.status).toBe(200);
  csrf = login.body.csrf_token;
}, 30000);
afterAll(async () => {
  await app?.close();
  await db.$disconnect();
  redis.disconnect();
});
describe("real PostgreSQL/Redis security integration", () => {
  it("rejects malformed and oversized JSON without leaking parser details", async () => {
    const malformed = await supertest(server)
      .post("/api/v1/auth/login")
      .set("Content-Type", "application/json")
      .send("{");
    expect(malformed.status).toBe(400);
    expect(malformed.body.error.code).toBe("INVALID_REQUEST");
    expect(malformed.body.error.request_id).toBe(
      malformed.headers["x-request-id"],
    );
    expect(malformed.body.error.request_id).toBeTruthy();
    expect(JSON.stringify(malformed.body)).not.toMatch(/stack|SyntaxError/);
    const oversized = await supertest(server)
      .post("/api/v1/auth/login")
      .send({ password: "x".repeat(40000) });
    expect(oversized.status).toBe(413);
    expect(oversized.body.error.code).toBe("PAYLOAD_TOO_LARGE");
  });
  it("denies USER administration and mass assignment", async () => {
    expect((await agent.get("/api/v1/admin/users")).status).toBe(403);
    const r = await agent
      .post("/api/v1/licenses")
      .set("Origin", config.origin)
      .set("X-CSRF-Token", csrf)
      .set("Idempotency-Key", uuid())
      .send({
        product_id: productId,
        duration_seconds: 3600,
        is_lifetime: false,
        user_id: otherId,
      });
    expect(r.status).toBe(400);
  });
  it("denies foreign resource access", async () => {
    const issued = await issue(
      otherId,
      {
        user_id: otherId,
        product_id: productId,
        duration_seconds: 3600,
        is_lifetime: false,
        reason: "Fixture",
      },
      true,
      uuid(),
    );
    expect(
      (await agent.get("/api/v1/licenses/" + issued.license.id)).status,
    ).toBe(404);
  });
  it("requires CSRF and entitlement", async () => {
    expect((await agent.post("/api/v1/licenses").send({})).status).toBe(403);
    expect(
      (
        await agent
          .post("/api/v1/licenses")
          .set("Origin", config.origin)
          .set("X-CSRF-Token", csrf)
          .set("Idempotency-Key", uuid())
          .send({
            product_id: productId,
            duration_seconds: 3600,
            is_lifetime: false,
          })
      ).status,
    ).toBe(403);
  });
  it("keeps key plaintext out of DB and activation starts duration", async () => {
    const r = await createLicense();
    const l = await db.license.findUniqueOrThrow({
      where: { id: r.license.id },
    });
    expect(l.activatedAt).toBeNull();
    expect(l.expiresAt).toBeNull();
    expect(Buffer.from(l.keyHash).length).toBe(32);
    const device = uuid();
    const a = await activate({
      license_key: r.license_key,
      product_id: productId,
      device_id: device,
    });
    expect(
      +new Date(a.license.expires_at!) - +new Date(a.license.activated_at!),
    ).toBe(3600000);
    expect(
      (
        await validate(a.session.token, {
          product_id: productId,
          device_id: device,
        })
      ).success,
    ).toBe(true);
    await expect(
      validate(a.session.token, { product_id: uuid(), device_id: device }),
    ).rejects.toMatchObject({ code: "INVALID_SESSION" });
  });
  it("serializes 50 concurrent devices without exceeding capacity", async () => {
    const r = await createLicense();
    // Exercise all 50 DB transactions; this fixture-specific limiter key is prepaid.
    await redis.set(
      "rl:activate-key:" +
        mac(config.fingerprint, normalizeLicense(r.license_key!)).toString(
          "hex",
        ),
      -100,
      "EX",
      60,
    );
    const results = await Promise.allSettled(
      Array.from({ length: 50 }, () =>
        activate({
          license_key: r.license_key,
          product_id: productId,
          device_id: uuid(),
        }),
      ),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(
      results.filter(
        (r) =>
          r.status === "rejected" && r.reason.code === "DEVICE_LIMIT_REACHED",
      ),
    ).toHaveLength(49);
    expect(
      await db.activation.count({
        where: { licenseId: r.license.id, revokedAt: null },
      }),
    ).toBe(1);
  }, 30000);
  it("repeated same-device activation preserves initial expiry", async () => {
    const r = await createLicense();
    const body = {
      license_key: r.license_key,
      product_id: productId,
      device_id: uuid(),
    };
    const a = await activate(body),
      b = await activate(body);
    expect(a.license.activated_at).toEqual(b.license.activated_at);
    expect(a.license.expires_at).toEqual(b.license.expires_at);
    expect(
      await db.activation.count({ where: { licenseId: r.license.id } }),
    ).toBe(1);
    await expect(validate(a.session.token, body)).rejects.toBeDefined();
  });
  it.each(["block", "revoke"])(
    "%s denies activation, validation and refresh",
    async (action) => {
      const r = await createLicense();
      const device = uuid(),
        a = await activate({
          license_key: r.license_key,
          product_id: productId,
          device_id: device,
        });
      await mutateLicense(userId, r.license.id, action, {
        reason: "Test denial",
        expected_version: 1,
      });
      await expect(
        activate({
          license_key: r.license_key,
          product_id: productId,
          device_id: device,
        }),
      ).rejects.toBeDefined();
      await expect(
        validate(a.session.token, { product_id: productId, device_id: device }),
      ).rejects.toBeDefined();
      await expect(
        appRefresh({
          refresh_token: a.refresh.token,
          product_id: productId,
          device_id: device,
        }),
      ).rejects.toBeDefined();
    },
  );
  it("rejects expired licenses independent of stored ACTIVE status", async () => {
    const r = await createLicense();
    const device = uuid(),
      a = await activate({
        license_key: r.license_key,
        product_id: productId,
        device_id: device,
      });
    await db.license.update({
      where: { id: r.license.id },
      data: {
        activatedAt: new Date(Date.now() - 7200000),
        expiresAt: new Date(Date.now() - 3600000),
      },
    });
    await expect(
      validate(a.session.token, { product_id: productId, device_id: device }),
    ).rejects.toMatchObject({ code: "LICENSE_EXPIRED" });
  });
  it("bounds lifetime offline proofs", async () => {
    const r = await createLicense({
      duration_seconds: null,
      is_lifetime: true,
    });
    const device = uuid(),
      a = await activate({
        license_key: r.license_key,
        product_id: productId,
        device_id: device,
      });
    const proof = await offline(a.session.token, {
      product_id: productId,
      device_id: device,
    });
    expect(+proof.valid_until - Date.now()).toBeLessThanOrEqual(86400000);
    expect(a.license.expires_at).toBeNull();
  });
  it("detects application refresh reuse and revokes the successor", async () => {
    const r = await createLicense(),
      device = uuid(),
      a = await activate({
        license_key: r.license_key,
        product_id: productId,
        device_id: device,
      });
    const body = {
      refresh_token: a.refresh.token,
      product_id: productId,
      device_id: device,
    };
    const fresh = await appRefresh(body);
    await expect(appRefresh(body)).rejects.toMatchObject({
      code: "INVALID_SESSION",
    });
    await expect(
      validate(fresh.session.token, {
        product_id: productId,
        device_id: device,
      }),
    ).rejects.toMatchObject({ code: "INVALID_SESSION" });
  });
  it("enforces database constraints and append-only audit permissions", async () => {
    await expect(
      db.user.create({
        data: { id: uuid(), login: "INVALID", passwordHash: "x" },
      }),
    ).rejects.toBeDefined();
    const id = uuid();
    await transaction((tx) => audit(tx, userId, "TestAppendOnly", "test", id));
    await expect(
      db.auditLog.deleteMany({ where: { targetId: id } }),
    ).rejects.toBeDefined();
    await expect(
      db.auditLog.updateMany({
        where: { targetId: id },
        data: { action: "Changed" },
      }),
    ).rejects.toBeDefined();
  });
  it("applies atomic Redis limits", async () => {
    const dimension = uuid();
    await limit("test", dimension, 2, 60);
    await limit("test", dimension, 2, 60);
    await expect(limit("test", dimension, 2, 60)).rejects.toMatchObject({
      code: "RATE_LIMITED",
    });
  });
  it("creation idempotency never returns plaintext twice", async () => {
    const id = uuid(),
      body = {
        user_id: userId,
        product_id: productId,
        duration_seconds: 3600,
        is_lifetime: false,
        reason: "Test idempotency",
      };
    const a = await issue(userId, body, true, id),
      b = await issue(userId, body, true, id);
    expect(a.license_key).toBeTruthy();
    expect(b.license_key).toBeUndefined();
    expect(b.license.id).toBe(a.license.id);
  });
  it("detects web refresh reuse and revokes new access", async () => {
    const login = await supertest(server)
      .post("/api/v1/auth/login")
      .set("Origin", config.origin)
      .send({ login: "test_" + run, password: pass });
    const cookies = (r: any) =>
      (r.headers["set-cookie"] as string[])
        .map((v) => v.split(";")[0])
        .join("; ");
    const old = cookies(login),
      c = login.body.csrf_token;
    const fresh = await supertest(server)
      .post("/api/v1/auth/refresh")
      .set("Origin", config.origin)
      .set("X-CSRF-Token", c)
      .set("Cookie", old)
      .send({});
    expect(fresh.status).toBe(200);
    const replay = await supertest(server)
      .post("/api/v1/auth/refresh")
      .set("Origin", config.origin)
      .set("X-CSRF-Token", c)
      .set("Cookie", old)
      .send({});
    expect(replay.status).toBe(401);
    expect(
      (
        await supertest(server)
          .get("/api/v1/auth/me")
          .set("Cookie", cookies(fresh))
      ).status,
    ).toBe(401);
  });
  it("requires and verifies a genuine WebAuthn signature before admin issuance", async () => {
    const adminId = uuid(),
      name = "admin_" + run;
    await db.user.create({
      data: {
        id: adminId,
        login: name,
        passwordHash: await passwordHash(pass),
        role: "ADMIN",
      },
    });
    const pair = generateKeyPairSync("ec", { namedCurve: "P-256" }),
      jwk = pair.publicKey.export({ format: "jwk" }),
      credentialId = randomBytes(32).toString("base64url");
    const cose = isoCBOR.encode(
      new Map<any, any>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(Buffer.from(jwk.x!, "base64url"))],
        [-3, new Uint8Array(Buffer.from(jwk.y!, "base64url"))],
      ]),
    );
    await db.credential.create({
      data: {
        id: credentialId,
        userId: adminId,
        publicKey: Buffer.from(cose),
        counter: 0n,
        transports: ["internal"],
      },
    });
    const a = supertest.agent(server);
    const logged = await a
      .post("/api/v1/auth/login")
      .set("Origin", config.origin)
      .send({ login: name, password: pass });
    const c = logged.body.csrf_token;
    expect((await a.get("/api/v1/admin/users")).body.error.code).toBe(
      "MFA_REQUIRED",
    );
    const challenge = await a
      .post("/api/v1/auth/mfa/challenge")
      .set("Origin", config.origin)
      .set("X-CSRF-Token", c)
      .send({});
    const client = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: challenge.body.challenge,
        origin: config.origin,
        crossOrigin: false,
      }),
    );
    const authenticator = Buffer.alloc(37);
    createHash("sha256").update(config.rpId).digest().copy(authenticator);
    authenticator[32] = 5;
    authenticator.writeUInt32BE(1, 33);
    const signature = sign(
      "sha256",
      Buffer.concat([
        authenticator,
        createHash("sha256").update(client).digest(),
      ]),
      pair.privateKey,
    );
    const assertion = {
      id: credentialId,
      rawId: credentialId,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: client.toString("base64url"),
        authenticatorData: authenticator.toString("base64url"),
        signature: signature.toString("base64url"),
        userHandle: Buffer.from(adminId).toString("base64url"),
      },
    };
    expect(
      (
        await a
          .post("/api/v1/auth/mfa/verify")
          .set("Origin", config.origin)
          .set("X-CSRF-Token", c)
          .send(assertion)
      ).status,
    ).toBe(201);
    expect((await a.get("/api/v1/admin/users")).status).toBe(200);
    const issued = await a
      .post("/api/v1/admin/licenses")
      .set("Origin", config.origin)
      .set("X-CSRF-Token", c)
      .set("Idempotency-Key", uuid())
      .send({
        user_id: userId,
        product_id: productId,
        duration_seconds: 3600,
        is_lifetime: false,
        reason: "MFA protected issuance",
      });
    expect(issued.status).toBe(201);
    expect(issued.body.license_key).toMatch(/^LK1-/);
    expect(
      (
        await a
          .post("/api/v1/auth/mfa/verify")
          .set("Origin", config.origin)
          .set("X-CSRF-Token", c)
          .send(assertion)
      ).status,
    ).toBe(400);
  });
  it("serializes self-issuance quota consumption", async () => {
    await db.entitlement.create({
      data: {
        id: uuid(),
        userId: otherId,
        productId,
        remaining: 1,
        durations: [3600],
        maxDevices: 1,
      },
    });
    const requests = await Promise.allSettled(
      Array.from({ length: 20 }, () =>
        issue(
          otherId,
          { product_id: productId, duration_seconds: 3600, is_lifetime: false },
          false,
          uuid(),
        ),
      ),
    );
    expect(requests.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(
      (
        await db.entitlement.findUniqueOrThrow({
          where: { userId_productId: { userId: otherId, productId } },
        })
      ).remaining,
    ).toBe(0);
  });
  it("unblocks never-activated and expired licenses correctly", async () => {
    const r = await createLicense();
    await mutateLicense(userId, r.license.id, "block", {
      reason: "Test",
      expected_version: 1,
    });
    const restored = await mutateLicense(userId, r.license.id, "unblock", {
      reason: "Test",
      expected_version: 2,
    });
    expect(restored.status).toBe("NOT_ACTIVATED");
    expect(restored.activated_at).toBeNull();
    await activate({
      license_key: r.license_key,
      product_id: productId,
      device_id: uuid(),
    });
    await mutateLicense(userId, r.license.id, "block", {
      reason: "Test",
      expected_version: 3,
    });
    await db.license.update({
      where: { id: r.license.id },
      data: {
        activatedAt: new Date(Date.now() - 7200000),
        expiresAt: new Date(Date.now() - 3600000),
      },
    });
    expect(
      (
        await mutateLicense(userId, r.license.id, "unblock", {
          reason: "Test",
          expected_version: 4,
        })
      ).status,
    ).toBe("EXPIRED");
  });
  it("revoked device cannot reactivate and disabled product cannot validate", async () => {
    const r = await createLicense(),
      device = uuid();
    const a = await activate({
      license_key: r.license_key,
      product_id: productId,
      device_id: device,
    });
    await db.activation.update({
      where: {
        licenseId_deviceId: { licenseId: r.license.id, deviceId: device },
      },
      data: { revokedAt: new Date() },
    });
    await expect(
      activate({
        license_key: r.license_key,
        product_id: productId,
        device_id: device,
      }),
    ).rejects.toMatchObject({ code: "DEVICE_REVOKED" });
    await expect(
      validate(a.session.token, { product_id: productId, device_id: device }),
    ).rejects.toBeDefined();
    const r2 = await createLicense(),
      d2 = uuid(),
      b = await activate({
        license_key: r2.license_key,
        product_id: productId,
        device_id: d2,
      });
    await db.product.update({
      where: { id: productId },
      data: { enabled: false },
    });
    try {
      await expect(
        validate(b.session.token, { product_id: productId, device_id: d2 }),
      ).rejects.toMatchObject({ code: "INVALID_LICENSE" });
    } finally {
      await db.product.update({
        where: { id: productId },
        data: { enabled: true },
      });
    }
  });
});
