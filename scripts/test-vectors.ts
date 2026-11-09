import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import {
  signLP1,
  canonical,
  KeyRecord,
} from "../packages/crypto-server/src/index";
const pair = generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const key: KeyRecord = {
  id: "vector-offline",
  purpose: "offline-license",
  status: "ACTIVE",
  ...pair,
  notBefore: 1000,
  verifyUntil: 9000000000,
};
const id = "01995bee-1111-7111-8111-111111111111";
const payload = {
  version: 1,
  issuer: "https://vectors.invalid",
  audience: "offline-license",
  license_id: id,
  user_id: id,
  product_id: id,
  device_id: id,
  issued_at: 2000000000,
  valid_until: 2000086400,
  license_expires_at: null,
  lifetime: true,
  license_version: 1,
  nonce: randomBytes(16).toString("base64url"),
};
const token = signLP1(key, payload);
const manifest = {
  version: 1,
  issuer: payload.issuer,
  issued_at: 1999999900,
  expires_at: 2100000000,
  keys: [{ ...key, privateKey: undefined }],
};
mkdirSync("packages/lp1-spec/vectors", { recursive: true });
writeFileSync(
  "packages/lp1-spec/vectors/offline.json",
  JSON.stringify(
    {
      now: 2000000001,
      product_id: id,
      device_id: id,
      issuer: payload.issuer,
      root_public_key: pair.publicKey,
      manifest: {
        payload: manifest,
        signature: sign(
          null,
          Buffer.from(canonical(manifest)),
          pair.privateKey,
        ).toString("base64url"),
      },
      token,
    },
    null,
    2,
  ),
);
console.log(
  "Public cross-language test vector written (private fixture key discarded).",
);
