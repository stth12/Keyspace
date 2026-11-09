import "dotenv/config";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import {
  canonical,
  KeyRecord,
} from "../../../packages/crypto-server/src/index";
function required(name: string) {
  const value = process.env[name];
  if (!value) throw Error(`Missing configuration: ${name}`);
  return value;
}
function secret(name: string) {
  const s = required(name);
  if (!/^[0-9a-f]{64}$/.test(s) || /^(.)\1+$/.test(s))
    throw Error(`Invalid secret format: ${name}`);
  return Buffer.from(s, "hex");
}
export const config = {
  production: process.env.NODE_ENV === "production",
  database: required("DATABASE_URL"),
  redis: required("REDIS_URL"),
  origin: required("WEB_ORIGIN"),
  issuer: required("API_ISSUER"),
  jwt: secret("JWT_ACCESS_SECRET"),
  hmac: secret("LICENSE_HMAC_SECRET"),
  hmacId: required("LICENSE_HMAC_ACTIVE_KEY_ID"),
  fingerprint: secret("OBSERVABILITY_SECRET"),
  master: secret("CHACHA_MASTER_KEY"),
  rpId: required("RP_ID"),
  port: Number(process.env.PORT || 4000),
  host:
    process.env.HOST ||
    (process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1"),
};
if (
  config.production &&
  (!config.origin.startsWith("https://") ||
    !config.issuer.startsWith("https://"))
)
  throw Error("Production requires HTTPS");
export const keyStore = JSON.parse(
  readFileSync(required("KEYSTORE_FILE"), "utf8"),
) as {
  keys: KeyRecord[];
  rootPublicKey: string;
  manifest: { payload: unknown; signature: string };
};
const manifestPayload = keyStore.manifest.payload as {
  issuer: string;
  expires_at: number;
  keys: Omit<KeyRecord, "privateKey">[];
};
if (
  manifestPayload.issuer !== config.issuer ||
  manifestPayload.expires_at <= Date.now() / 1000
)
  throw Error("Wrong issuer or expired key manifest");
for (const key of keyStore.keys) {
  const { privateKey, ...publicRecord } = key;
  if (
    !manifestPayload.keys.some((k) => canonical(k) === canonical(publicRecord))
  )
    throw Error("Manifest key mismatch");
}
if (
  !verify(
    null,
    Buffer.from(canonical(keyStore.manifest.payload)),
    keyStore.rootPublicKey,
    Buffer.from(keyStore.manifest.signature, "base64url"),
  )
)
  throw Error("Invalid key manifest");
for (const purpose of ["application-session", "offline-license"]) {
  const active = keyStore.keys.filter(
    (k) => k.purpose === purpose && k.status === "ACTIVE",
  );
  if (active.length !== 1 || !active[0].privateKey)
    throw Error("Invalid signing configuration");
  const k = active[0];
  const probe = Buffer.from("startup-self-test");
  if (
    !verify(
      null,
      probe,
      createPublicKey(k.publicKey),
      sign(null, probe, createPrivateKey(k.privateKey!)),
    )
  )
    throw Error("Key pair mismatch");
}
export const hmacKeys = new Map<string, Buffer>([[config.hmacId, config.hmac]]);
for (const [id, value] of Object.entries(
  JSON.parse(process.env.LICENSE_HMAC_PREVIOUS_JSON || "{}"),
)) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{64}$/.test(value) ||
    hmacKeys.size >= 4 ||
    hmacKeys.has(id)
  )
    throw Error("Invalid HMAC key ring");
  hmacKeys.set(id, Buffer.from(value, "hex"));
}
