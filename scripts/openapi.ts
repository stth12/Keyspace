import { writeFileSync, mkdirSync } from "node:fs";
import { createApp } from "../apps/api/src/app";
import { db } from "../apps/api/src/database";
import { redis } from "../apps/api/src/security";
async function main() {
  const { app, doc } = await createApp();
  mkdirSync("docs/api", { recursive: true });
  writeFileSync("docs/api/openapi.json", JSON.stringify(doc, null, 2));
  await app.close();
  await db.$disconnect();
  redis.disconnect();
}
main().catch(() => process.exit(1));
