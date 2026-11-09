import { describe, it, expect } from "vitest";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
  generateLicense,
  normalizeLicense,
  mac,
  hash,
  canonical,
  signLP1,
  verifyLP1,
  seal,
  unseal,
  KeyRecord,
} from "../packages/crypto-server/src/index";
const kp = generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const key: KeyRecord = {
  id: "test-key",
  purpose: "application-session",
  status: "ACTIVE",
  ...kp,
  notBefore: 1,
  verifyUntil: 9999999999,
};
const now = Math.floor(Date.now() / 1000),
  id = "01995bee-1111-7111-8111-111111111111";
const payload = {
  issuer: "https://test.invalid",
  audience: "application-api",
  session_id: id,
  license_id: id,
  user_id: id,
  product_id: id,
  device_id: id,
  issued_at: now,
  expires_at: now + 300,
  license_version: 1,
  nonce: randomBytes(16).toString("base64url"),
};
describe("LP1 and LK1", () => {
  it("generates 160-bit grouped keys and normalizes only allowed syntax", () => {
    const seen = new Set();
    for (let i = 0; i < 1000; i++) {
      const k = generateLicense();
      expect(k).toMatch(/^LK1-(?:[A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
      seen.add(k);
      expect(normalizeLicense(k.toLowerCase())).toHaveLength(36);
    }
    expect(seen.size).toBe(1000);
    expect(() => normalizeLicense("LK1-АBCD-1234")).toThrow();
  });
  it("HMAC matches RFC 4231 vector", () => {
    expect(mac(Buffer.alloc(20, 0x0b), "Hi There").toString("hex")).toBe(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
  });
  it("verifies a signed application session", () => {
    const t = signLP1(key, payload);
    expect(verifyLP1(t, [key], key.purpose, payload.issuer)).toEqual(payload);
  });
  it("rejects modified payload, signature, purpose and issuer", () => {
    const t = signLP1(key, payload),
      p = t.split(".");
    p[2] = Buffer.from(canonical({ ...payload, license_version: 2 })).toString(
      "base64url",
    );
    expect(() =>
      verifyLP1(p.join("."), [key], key.purpose, payload.issuer),
    ).toThrow();
    const sig = t.split(".");
    sig[3] = randomBytes(64).toString("base64url");
    expect(() =>
      verifyLP1(sig.join("."), [key], key.purpose, payload.issuer),
    ).toThrow();
    expect(() =>
      verifyLP1(t, [key], "offline-license", payload.issuer),
    ).toThrow();
    expect(() => verifyLP1(t, [key], key.purpose, "evil")).toThrow();
  });
  it("rejects revoked keys, expired TTL and padded encoding", () => {
    const t = signLP1(key, payload);
    expect(() =>
      verifyLP1(
        t,
        [{ ...key, status: "REVOKED" }],
        key.purpose,
        payload.issuer,
      ),
    ).toThrow();
    expect(() =>
      verifyLP1(t, [key], key.purpose, payload.issuer, now + 300),
    ).toThrow();
    expect(() =>
      verifyLP1(t + "=", [key], key.purpose, payload.issuer),
    ).toThrow();
  });
  it("rejects duplicate JSON keys even if signed by trusted key", () => {
    const t = signLP1(key, payload).split(".");
    t[2] = Buffer.from(
      canonical(payload).replace("{", '{"issuer":"evil",'),
    ).toString("base64url");
    t[3] = sign(
      null,
      Buffer.from(t.slice(0, 3).join(".")),
      kp.privateKey,
    ).toString("base64url");
    expect(() =>
      verifyLP1(t.join("."), [key], key.purpose, payload.issuer),
    ).toThrow();
  });
  it("enforces bounded lifetime offline proof", () => {
    const k = { ...key, purpose: "offline-license" as const };
    const p = {
      version: 1,
      issuer: payload.issuer,
      audience: "offline-license",
      license_id: id,
      user_id: id,
      product_id: id,
      device_id: id,
      issued_at: now,
      valid_until: now + 604800,
      license_expires_at: null,
      lifetime: true,
      license_version: 1,
      nonce: payload.nonce,
    };
    expect(verifyLP1(signLP1(k, p), [k], k.purpose, p.issuer)).toEqual(p);
    expect(() =>
      verifyLP1(
        signLP1(k, { ...p, valid_until: now + 604801 }),
        [k],
        k.purpose,
        p.issuer,
      ),
    ).toThrow();
  });
  it("AEAD authenticates plaintext and associated data", () => {
    const master = randomBytes(32),
      context = { purpose: "test", record_id: id };
    const e = seal(master, Buffer.from("confidential"), context);
    expect(unseal(master, e, context).toString()).toBe("confidential");
    expect(() => unseal(master, e, { purpose: "other" })).toThrow();
    expect(() => unseal(randomBytes(32), e, context)).toThrow();
    expect(() =>
      unseal(
        master,
        { ...e, tag: randomBytes(16).toString("base64url") },
        context,
      ),
    ).toThrow();
  });
});
