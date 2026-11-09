import "dotenv/config";
import { readFileSync, writeFileSync } from "node:fs";
import { db } from "../apps/api/src/database";
async function main() {
  const product = await db.product.findFirst({
    where: {
      enabled: true,
      slug: process.env.DESKTOP_PRODUCT_SLUG || "keyspace",
    },
    orderBy: { createdAt: "asc" },
  });
  if (!product) throw Error("Create a product first");
  const store = JSON.parse(readFileSync(process.env.KEYSTORE_FILE!, "utf8"));
  writeFileSync(
    "apps/desktop/src-tauri/client-config.json",
    JSON.stringify(
      {
        api_url: process.env.API_ISSUER,
        issuer: process.env.API_ISSUER,
        product_id: product.id,
        root_public_key: store.rootPublicKey,
      },
      null,
      2,
    ),
  );
  console.log(
    "Public desktop configuration generated; contains no server secrets.",
  );
}
main().finally(() => db.$disconnect());
