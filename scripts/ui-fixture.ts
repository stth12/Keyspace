import { db, transaction, audit } from "../apps/api/src/database";
import { passwordHash } from "../apps/api/src/auth";
import { config } from "../apps/api/src/config";
import { v7 as uuid } from "uuid";
import { redis } from "../apps/api/src/security";
async function main() {
  if (config.production) throw Error("Development only");
  const product = await db.product.findUniqueOrThrow({
    where: { slug: "keyspace" },
  });
  const login = "ui_" + Date.now().toString(36);
  const u = await db.user.create({
    data: {
      id: uuid(),
      login,
      passwordHash: await passwordHash("Test-only-validation-2026!"),
    },
  });
  await db.entitlement.create({
    data: {
      id: uuid(),
      userId: u.id,
      productId: product.id,
      remaining: 2,
      durations: [3600, 86400],
      maxDevices: 1,
    },
  });
  await transaction((tx) => audit(tx, null, "UiTestFixture", "user", u.id));
  console.log(login);
}
main().finally(async () => {
  await db.$disconnect();
  redis.disconnect();
});
