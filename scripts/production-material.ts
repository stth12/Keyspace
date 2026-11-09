import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { canonical } from "../packages/crypto-server/src/index";
import { login } from "../packages/contracts/src/index";

export function validateSettings(input: any) {
  const domain = String(input.domain).toLowerCase();
  if (domain.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain))
    throw Error("Invalid DNS domain");
  const auditMode = input.auditMode ?? "external";
  if (!["external", "database-only"].includes(auditMode)) throw Error("Invalid audit mode");
  const sink = auditMode === "database-only" && input.auditUrl === "" ? null : new URL(input.auditUrl);
  if (sink && (sink.protocol !== "https:" || sink.username || sink.password || sink.hash))
    throw Error("Audit sink requires HTTPS without credentials or fragment");
  if (!/^[a-z0-9-]{3,64}$/.test(input.slug)) throw Error("Invalid product slug");
  if (typeof input.name !== "string" || input.name.length < 1 || input.name.length > 100)
    throw Error("Invalid product name");
  if (typeof input.offline !== "boolean") throw Error("Invalid offline setting");
  if (typeof input.auditToken !== "string" || /[\r\n\x00']/.test(input.auditToken))
    throw Error("Unsupported audit token characters");
  if (/[\r\n\x00']/.test(sink?.href ?? "")) throw Error("Unsupported audit URL characters");
  return { domain, auditMode, auditUrl: sink?.href ?? "", auditToken: input.auditToken,
    admin: login.parse(input.admin), slug: input.slug, name: input.name, offline: input.offline };
}

export function productionMaterial(input: unknown) {
  const settings = validateSettings(input);
  const secret = () => randomBytes(32).toString("hex");
  const pair = () => generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  const root = pair();
  const now = Math.floor(Date.now() / 1000);
  const keys = ["application-session", "offline-license"].map(purpose => ({
    id: purpose + "-1", purpose, status: "ACTIVE", ...pair(),
    notBefore: now - 60, verifyUntil: now + 365 * 86400,
  }));
  const issuer = `https://${settings.domain}`;
  const payload = { version: 1, issuer, issued_at: now, expires_at: now + 365 * 86400,
    keys: keys.map(({ privateKey, ...publicKey }) => publicKey) };
  const store = { keys, rootPublicKey: root.publicKey, manifest: { payload,
    signature: sign(null, Buffer.from(canonical(payload)), root.privateKey).toString("base64url") } };
  const pg = secret(), runtime = secret(), redis = secret();
  const env: Record<string, string> = {
    NODE_ENV: "production", DOMAIN: settings.domain, WEB_ORIGIN: issuer, API_ISSUER: issuer,
    RP_ID: settings.domain, PORT: "4000", KEYSTORE_FILE: ".secrets/keystore.json",
    POSTGRES_PASSWORD: pg, RUNTIME_DB_PASSWORD: runtime, REDIS_PASSWORD: redis,
    DATABASE_URL: `postgresql://lk_runtime:${runtime}@postgres:5432/licensing`,
    MIGRATION_DATABASE_URL: `postgresql://postgres:${pg}@postgres:5432/licensing`,
    REDIS_URL: `redis://:${redis}@redis:6379`, JWT_ACCESS_SECRET: secret(),
    LICENSE_HMAC_SECRET: secret(), LICENSE_HMAC_ACTIVE_KEY_ID: "hmac-1",
    LICENSE_HMAC_PREVIOUS_JSON: "{}", OBSERVABILITY_SECRET: secret(), CHACHA_MASTER_KEY: secret(),
    AUDIT_MODE: settings.auditMode, AUDIT_SINK_URL: settings.auditUrl, AUDIT_SINK_TOKEN: settings.auditToken,
  };
  return { store, root, env: Object.entries(env).map(([k, v]) => `${k}='${v}'`).join("\n") + "\n" };
}
