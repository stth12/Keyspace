import { describe, expect, it } from "vitest";
import { verify } from "node:crypto";
import { parse } from "dotenv";
import { productionMaterial, validateSettings } from "../scripts/production-material";
import { canonical } from "../packages/crypto-server/src/index";

const input = { domain: "licenses.example.com", admin: "Admin", slug: "example",
  name: "Example", offline: true, auditUrl: "https://audit.example.com/events", auditToken: "token$literal#value" };
describe("production provisioning material", () => {
  it("requires explicit opt-in for database-only test audit", () => {
    expect(() => productionMaterial({ ...input, auditUrl: "" })).toThrow();
    const result = productionMaterial({ ...input, auditMode: "database-only", auditUrl: "", auditToken: "" });
    expect(parse(result.env).AUDIT_MODE).toBe("database-only");
    expect(parse(result.env).AUDIT_SINK_URL).toBe("");
  });
  it("signs the production issuer and keeps private keys out of the manifest", () => {
    const { store, env } = productionMaterial(input);
    expect(store.manifest.payload.issuer).toBe("https://licenses.example.com");
    expect(JSON.stringify(store.manifest)).not.toContain("PRIVATE KEY");
    expect(verify(null, Buffer.from(canonical(store.manifest.payload)), store.rootPublicKey,
      Buffer.from(store.manifest.signature, "base64url"))).toBe(true);
    const tampered = { ...store.manifest.payload, issuer: "https://attacker.example.com" };
    expect(verify(null, Buffer.from(canonical(tampered)), store.rootPublicKey,
      Buffer.from(store.manifest.signature, "base64url"))).toBe(false);
    expect(parse(env).AUDIT_SINK_TOKEN).toBe(input.auditToken);
    expect(parse(env).API_ISSUER).not.toContain("localhost");
  });
  it("creates independent secrets and distinct installations", () => {
    const first = parse(productionMaterial(input).env), second = parse(productionMaterial(input).env);
    const names = ["JWT_ACCESS_SECRET", "LICENSE_HMAC_SECRET", "OBSERVABILITY_SECRET", "CHACHA_MASTER_KEY",
      "POSTGRES_PASSWORD", "RUNTIME_DB_PASSWORD", "REDIS_PASSWORD"];
    expect(new Set(names.map(n => first[n])).size).toBe(names.length);
    for (const name of names) {
      expect(first[name]).toMatch(/^[a-f0-9]{64}$/);
      expect(first[name]).not.toBe(second[name]);
    }
  });
  it("rejects config injection and invalid inputs", () => {
    for (const change of [{ domain: "example.com\nEVIL=1" }, { auditToken: "x'\nEVIL=1" },
      { auditUrl: "http://audit.example.com" }, { auditUrl: "https://user:pass@example.com" },
      { admin: "админ" }, { slug: "../../etc" }, { offline: "false" }]) {
      expect(() => validateSettings({ ...input, ...change })).toThrow();
    }
  });
});
