import "dotenv/config";
import { existsSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { v7 as uuid } from "uuid";
import { db, transaction, audit } from "../apps/api/src/database";
import { passwordHash } from "../apps/api/src/auth";
import { redis } from "../apps/api/src/security";
import { randomToken, hash } from "../packages/crypto-server/src/index";

let stage = "read-settings";
async function main() {
  const settings = JSON.parse(readFileSync(".secrets/install-settings.json", "utf8"));
  const credentialPath = ".secrets/install-admin.json";
  stage = "find-admin";
  let user = await db.user.findUnique({ where: { login: settings.admin } });
  if (!user && !existsSync(credentialPath)) {
    stage = "write-admin-credentials";
    writeFileSync(credentialPath, JSON.stringify({ login: settings.admin, password: randomToken(), user_id: uuid() }), { mode: 0o600, flag: "wx" });
  }
  if (!user) {
    const credentials = JSON.parse(readFileSync(credentialPath, "utf8"));
    stage = "hash-password";
    const password = await passwordHash(credentials.password);
    stage = "create-admin";
    user = await transaction(async tx => {
      const u = await tx.user.create({ data: { id: credentials.user_id, login: settings.admin, passwordHash: password, role: "ADMIN" } });
      await audit(tx, u.id, "AdminBootstrap", "user", u.id);
      return u;
    });
  }
  if (user.role !== "ADMIN") throw Error("Existing account is not an administrator");
  // Never reset a password. Only the original, still-present bootstrap file
  // allows enrollment renewal after an interrupted installation.
  stage = "check-mfa";
  if (existsSync(credentialPath) && await db.credential.count({ where: { userId: user.id } }) === 0) {
    const credentials = JSON.parse(readFileSync(credentialPath, "utf8"));
    if (credentials.user_id !== user.id) throw Error("Bootstrap identity mismatch");
    credentials.bootstrap = randomToken();
    stage = "redis-ready";
    if (redis.status !== "ready") {
      await new Promise<void>((resolve, reject) => {
        const cleanup = () => { clearTimeout(timer); redis.off("ready", ready); redis.off("error", failed); };
        const ready = () => { cleanup(); resolve(); };
        const failed = () => { cleanup(); reject(Error("Redis unavailable")); };
        const timer = setTimeout(failed, 10000);
        redis.once("ready", ready);
        redis.once("error", failed);
      });
    }
    stage = "write-bootstrap-redis";
    await redis.set("bootstrap:" + user.id, hash(credentials.bootstrap).toString("hex"), "EX", 900);
    stage = "save-bootstrap-file";
    writeFileSync(credentialPath + ".new", JSON.stringify(credentials, null, 2), { mode: 0o600 });
    renameSync(credentialPath + ".new", credentialPath);
  }
  stage = "create-product";
  const product = await transaction(async tx => {
    const existing = await tx.product.findUnique({ where: { slug: settings.slug } });
    if (existing) return existing;
    const p = await tx.product.create({ data: { id: uuid(), slug: settings.slug, name: settings.name, offlineEnabled: settings.offline } });
    await audit(tx, user!.id, "ProductCreated", "product", p.id);
    return p;
  });
  stage = "export-client-config";
  const store = JSON.parse(readFileSync(process.env.KEYSTORE_FILE!, "utf8"));
  writeFileSync(".secrets/client-config.json", JSON.stringify({ api_url: process.env.API_ISSUER,
    issuer: process.env.API_ISSUER, product_id: product.id, root_public_key: store.rootPublicKey }, null, 2), { mode: 0o600 });
  console.log("Administrator and product ready; public client configuration saved.");
}
main().catch((error: unknown) => {
  const code = error && typeof error === "object" && "code" in error ? String(error.code) : "UNKNOWN";
  console.error(`Bootstrap failed: stage=${stage}, code=${/^[A-Z0-9_]{1,32}$/.test(code) ? code : "UNKNOWN"}. No secret values logged.`);
  process.exitCode = 1;
})
  .finally(async () => { await db.$disconnect(); redis.disconnect(); });
