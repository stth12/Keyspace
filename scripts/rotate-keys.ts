import "dotenv/config";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { Client } from "pg";
import { v7 as uuid } from "uuid";
import { canonical } from "../packages/crypto-server/src/index";
async function main() {
  const [operation, purposeOrId] = process.argv.slice(2);
  if (!["rotate", "revoke", "manifest"].includes(operation))
    throw Error("Invalid operation");
  const path = process.env.KEYSTORE_FILE!;
  const store = JSON.parse(readFileSync(path, "utf8"));
  const now = Math.floor(Date.now() / 1000);
  let created: any;
  if (operation === "rotate") {
    if (!["application-session", "offline-license"].includes(purposeOrId))
      throw Error("Invalid purpose");
    for (const k of store.keys)
      if (k.purpose === purposeOrId && k.status === "ACTIVE") {
        k.status = "VERIFY_ONLY";
        delete k.privateKey;
      }
    const pair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { format: "pem", type: "pkcs8" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    created = {
      id: purposeOrId + "-" + now,
      purpose: purposeOrId,
      status: "ACTIVE",
      ...pair,
      notBefore: now - 30,
      verifyUntil: now + 365 * 86400,
    };
    store.keys.push(created);
  } else if (operation === "revoke") {
    const k = store.keys.find((k: any) => k.id === purposeOrId);
    if (!k || k.status === "ACTIVE")
      throw Error("Rotate active key before revoking");
    k.status = "REVOKED";
    delete k.privateKey;
  }
  const root = readFileSync(
    process.env.MANIFEST_ROOT_PRIVATE_KEY_FILE || ".secrets/manifest-root.pem",
    "utf8",
  );
  const payload = {
    version: store.manifest.payload.version + 1,
    issuer: process.env.API_ISSUER,
    issued_at: now,
    expires_at: now + 365 * 86400,
    keys: store.keys.map(({ privateKey, ...k }: any) => k),
  };
  store.manifest = {
    payload,
    signature: sign(null, Buffer.from(canonical(payload)), root).toString(
      "base64url",
    ),
  };
  const c = new Client({
    connectionString: process.env.MIGRATION_DATABASE_URL,
  });
  await c.connect();
  try {
    await c.query("BEGIN");
    await c.query(
      "UPDATE signing_keys SET status='VERIFY_ONLY' WHERE status='ACTIVE'",
    );
    for (const k of store.keys)
      await c.query(
        'INSERT INTO signing_keys (id,purpose,"publicKey",status,"notBefore","verifyUntil") VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status',
        [
          k.id,
          k.purpose,
          k.publicKey,
          k.status,
          new Date(k.notBefore * 1000),
          new Date(k.verifyUntil * 1000),
        ],
      );
    if (operation === "revoke")
      await c.query(
        'UPDATE application_sessions SET "revokedAt"=clock_timestamp() WHERE "revokedAt" IS NULL',
      );
    const auditId = uuid();
    const metadata = {
      operation,
      purpose_or_id: purposeOrId ?? null,
      manifest_version: payload.version,
      operator: "operator-cli",
    };
    await c.query(
      'INSERT INTO audit_logs (id,action,"targetType","targetId",metadata) VALUES ($1,$2,$3,$4,$5)',
      [
        auditId,
        "SigningKeyManagement",
        "signing_key",
        created?.id ?? purposeOrId ?? null,
        metadata,
      ],
    );
    await c.query(
      'INSERT INTO outbox_events (id,"auditId",payload) VALUES ($1,$2,$3)',
      [
        uuid(),
        auditId,
        {
          id: auditId,
          actor_user_id: null,
          action: "SigningKeyManagement",
          target_type: "signing_key",
          metadata,
        },
      ],
    );
    writeFileSync(path + ".new", JSON.stringify(store, null, 2), {
      mode: 0o600,
    });
    await c.query("COMMIT");
    renameSync(path + ".new", path);
    console.log(
      "Key store updated. Restart API replicas and redistribute public manifest. Never delete retired public keys before token expiry.",
    );
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    await c.end();
  }
}
main().catch(() => {
  console.error(
    "Rotation failed; inspect state before retry. No secret values logged.",
  );
  process.exit(1);
});
