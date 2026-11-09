import {
  createHmac,
  createHash,
  randomBytes,
  timingSafeEqual,
  sign,
  verify,
  createPrivateKey,
  createPublicKey,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";
import canonicalize from "canonicalize";
import { z } from "zod";
import { sessionClaims, offlineClaims } from "../../contracts/src/index";
export const canonical = (value: unknown): string => {
  const result = canonicalize(value);
  if (!result) throw Error("INVALID_JSON");
  return result;
};
export const randomToken = () => randomBytes(32).toString("base64url");
export const hash = (s: string) => createHash("sha256").update(s).digest();
export const mac = (key: Buffer, s: string) =>
  createHmac("sha256", key).update(s).digest();
export const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && timingSafeEqual(a, b);
export function generateLicense() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0,
    value = 0,
    out = "";
  for (const b of randomBytes(20)) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return "LK1-" + out.match(/.{4}/g)!.join("-");
}
export function normalizeLicense(raw: string) {
  const s = raw.trim().toUpperCase();
  if (!/^LK1-(?:[A-Z2-7]{32}|[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7})$/.test(s))
    throw Error("INVALID_LICENSE");
  return "LK1-" + s.slice(4).replaceAll("-", "");
}
const headerSchema = z
  .object({
    version: z.literal(1),
    type: z.enum(["application-session", "offline-license"]),
    signature_algorithm: z.literal("Ed25519"),
    encryption_algorithm: z.literal("none"),
    key_id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  })
  .strict();
export type KeyRecord = {
  id: string;
  purpose: "application-session" | "offline-license";
  publicKey: string;
  privateKey?: string;
  status: "ACTIVE" | "VERIFY_ONLY" | "REVOKED";
  notBefore: number;
  verifyUntil: number;
};
function decode(s: string, max: number) {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw Error("INVALID_TOKEN");
  const b = Buffer.from(s, "base64url");
  if (b.length > max || b.toString("base64url") !== s)
    throw Error("INVALID_TOKEN");
  return b;
}
function parseCanonical(b: Buffer) {
  const text = b.toString("utf8");
  const obj = JSON.parse(text);
  if (canonical(obj) !== text) throw Error("NON_CANONICAL_JSON");
  return obj;
}
export function signLP1(key: KeyRecord, payload: unknown) {
  if (!key.privateKey || key.status !== "ACTIVE")
    throw Error("SIGNER_UNAVAILABLE");
  const h = {
    version: 1,
    type: key.purpose,
    signature_algorithm: "Ed25519",
    encryption_algorithm: "none",
    key_id: key.id,
  };
  const p =
    key.purpose === "application-session"
      ? sessionClaims.parse(payload)
      : offlineClaims.parse(payload);
  const input =
    "LP1." +
    Buffer.from(canonical(h)).toString("base64url") +
    "." +
    Buffer.from(canonical(p)).toString("base64url");
  return (
    input +
    "." +
    sign(null, Buffer.from(input), createPrivateKey(key.privateKey)).toString(
      "base64url",
    )
  );
}
export function verifyLP1(
  token: string,
  keys: KeyRecord[],
  type: KeyRecord["purpose"],
  issuer: string,
  now = Math.floor(Date.now() / 1000),
) {
  if (token.length > 8192) throw Error("INVALID_TOKEN");
  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "LP1") throw Error("INVALID_TOKEN");
  const h = headerSchema.parse(parseCanonical(decode(parts[1], 512)));
  if (h.type !== type) throw Error("INVALID_TOKEN");
  const key = keys.find(
    (k) => k.id === h.key_id && k.purpose === type && k.status !== "REVOKED",
  );
  if (!key || now < key.notBefore || now >= key.verifyUntil)
    throw Error("INVALID_KEY");
  const sig = decode(parts[3], 64);
  if (
    sig.length !== 64 ||
    !verify(
      null,
      Buffer.from(parts.slice(0, 3).join(".")),
      createPublicKey(key.publicKey),
      sig,
    )
  )
    throw Error("INVALID_SIGNATURE");
  const p =
    type === "application-session"
      ? sessionClaims.parse(parseCanonical(decode(parts[2], 4096)))
      : offlineClaims.parse(parseCanonical(decode(parts[2], 4096)));
  const end = "expires_at" in p ? p.expires_at : p.valid_until;
  if (
    p.issuer !== issuer ||
    p.issued_at > now + 30 ||
    end <= now ||
    end <= p.issued_at ||
    p.issued_at < key.notBefore ||
    end > key.verifyUntil
  )
    throw Error("TOKEN_EXPIRED");
  if ("expires_at" in p && end - p.issued_at > 300) throw Error("INVALID_TTL");
  if (
    "lifetime" in p &&
    (end - p.issued_at > 604800 ||
      (p.lifetime
        ? p.license_expires_at !== null
        : p.license_expires_at === null || end > p.license_expires_at))
  )
    throw Error("INVALID_TTL");
  return p;
}
// Each envelope has a fresh DEK. Wrapping uses AES-KW to avoid a second nonce namespace.
// The confidential payload itself uses ChaCha20-Poly1305; AES-KW is only key wrapping.
export function seal(master: Buffer, plaintext: Buffer, context: unknown) {
  const dek = randomBytes(32),
    nonce = randomBytes(12),
    aad = Buffer.from(canonical(context));
  const wrap = createCipheriv("id-aes256-wrap", master, Buffer.alloc(8, 0xa6));
  const wrapped = Buffer.concat([wrap.update(dek), wrap.final()]);
  const cipher = createCipheriv("chacha20-poly1305", dek, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    nonce: nonce.toString("base64url"),
    wrapped_key: wrapped.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}
export function unseal(
  master: Buffer,
  e: ReturnType<typeof seal>,
  context: unknown,
) {
  const unwrap = createDecipheriv(
    "id-aes256-wrap",
    master,
    Buffer.alloc(8, 0xa6),
  );
  const dek = Buffer.concat([
    unwrap.update(Buffer.from(e.wrapped_key, "base64url")),
    unwrap.final(),
  ]);
  const cipher = createDecipheriv(
    "chacha20-poly1305",
    dek,
    Buffer.from(e.nonce, "base64url"),
    { authTagLength: 16 },
  );
  cipher.setAAD(Buffer.from(canonical(context)), {
    plaintextLength: Buffer.from(e.ciphertext, "base64url").length,
  });
  cipher.setAuthTag(Buffer.from(e.tag, "base64url"));
  return Buffer.concat([
    cipher.update(Buffer.from(e.ciphertext, "base64url")),
    cipher.final(),
  ]);
}
