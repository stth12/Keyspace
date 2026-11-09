import "dotenv/config";
import { readdir, readFile } from "node:fs/promises";
const secrets = [
  "JWT_ACCESS_SECRET",
  "LICENSE_HMAC_SECRET",
  "OBSERVABILITY_SECRET",
  "CHACHA_MASTER_KEY",
  "RUNTIME_DB_PASSWORD",
  "POSTGRES_PASSWORD",
  "REDIS_PASSWORD",
]
  .map((n) => process.env[n])
  .filter((v) => v && v.length >= 16);
const store = JSON.parse(await readFile(process.env.KEYSTORE_FILE, "utf8"));
for (const key of store.keys)
  if (key.privateKey) {
    secrets.push(key.privateKey);
    secrets.push(
      key.privateKey
        .split("\n")
        .filter((s) => s && !s.startsWith("---"))
        .join(""),
    );
  }
async function files(dir) {
  const result = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const p = dir + "/" + entry.name;
    if (entry.isDirectory()) result.push(...(await files(p)));
    else result.push(p);
  }
  return result;
}
let checked = 0;
for (const dir of ["apps/web/.next/static", "apps/desktop/dist"]) {
  for (const path of await files(dir)) {
    const bytes = await readFile(path);
    checked++;
    if (secrets.some((s) => bytes.includes(Buffer.from(s))))
      throw Error("Server secret found in client asset: " + path);
    if (bytes.includes(Buffer.from("-----BEGIN PRIVATE KEY-----")))
      throw Error("Private key marker in client asset: " + path);
  }
}
console.log(
  `Checked ${checked} client assets: no configured server secrets or private-key markers found.`,
);
