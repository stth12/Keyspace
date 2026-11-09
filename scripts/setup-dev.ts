import { randomBytes, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { canonical } from "../packages/crypto-server/src/index";
if (existsSync(".env") || existsSync(".secrets/keystore.json"))
  throw Error("Existing environment is not overwritten");
mkdirSync(".secrets", { recursive: true });
const now = Math.floor(Date.now() / 1000),
  until = now + 365 * 86400;
const pair = () =>
  generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
const keys = ["application-session", "offline-license"].map((purpose) => {
  const k = pair();
  return {
    id: purpose + "-1",
    purpose,
    status: "ACTIVE",
    privateKey: k.privateKey,
    publicKey: k.publicKey,
    notBefore: now - 60,
    verifyUntil: until,
  };
});
const root = pair();
const manifest = {
  version: 1,
  issuer: "http://localhost:4000",
  issued_at: now,
  expires_at: until,
  keys: keys.map(({ privateKey, ...k }) => k),
};
writeFileSync(
  ".secrets/keystore.json",
  JSON.stringify(
    {
      keys,
      manifest: {
        payload: manifest,
        signature: sign(
          null,
          Buffer.from(canonical(manifest)),
          root.privateKey,
        ).toString("base64url"),
      },
      rootPublicKey: root.publicKey,
    },
    null,
    2,
  ),
  { mode: 0o600 },
);
writeFileSync(".secrets/manifest-root.pem", root.privateKey, { mode: 0o600 });
writeFileSync(".secrets/manifest-root-public.pem", root.publicKey);
const secret = () => randomBytes(32).toString("hex");
const pg = secret(),
  runtime = secret(),
  redis = secret();
writeFileSync(
  ".env",
  `NODE_ENV=development\nDATABASE_URL=postgresql://lk_runtime:${runtime}@localhost:15432/licensing\nMIGRATION_DATABASE_URL=postgresql://postgres:${pg}@localhost:15432/licensing\nPOSTGRES_PASSWORD=${pg}\nRUNTIME_DB_PASSWORD=${runtime}\nREDIS_PASSWORD=${redis}\nREDIS_URL=redis://:${redis}@localhost:56379\nWEB_ORIGIN=http://localhost:3000\nAPI_ISSUER=http://localhost:4000\nPORT=4000\nRP_ID=localhost\nKEYSTORE_FILE=.secrets/keystore.json\nJWT_ACCESS_SECRET=${secret()}\nLICENSE_HMAC_SECRET=${secret()}\nLICENSE_HMAC_ACTIVE_KEY_ID=hmac-1\nLICENSE_HMAC_PREVIOUS_JSON={}\nOBSERVABILITY_SECRET=${secret()}\nCHACHA_MASTER_KEY=${secret()}\n`,
  { mode: 0o600 },
);
console.log(
  "Development secrets created in ignored files. No credentials printed.",
);
