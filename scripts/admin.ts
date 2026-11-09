import "dotenv/config";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { writeFileSync } from "node:fs";
import { v7 as uuid } from "uuid";
import { db, transaction, audit } from "../apps/api/src/database";
import { redis } from "../apps/api/src/security";
import { passwordHash } from "../apps/api/src/auth";
import { login, password } from "../packages/contracts/src/index";
import { randomToken, hash } from "../packages/crypto-server/src/index";
async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "create") {
    const name = login.parse(args[0]);
    const pass = password.parse(randomToken());
    const u = await transaction(async (tx) => {
      const user = await tx.user.create({
        data: {
          id: uuid(),
          login: name,
          passwordHash: await passwordHash(pass),
          role: "ADMIN",
        },
      });
      await audit(tx, user.id, "AdminBootstrap", "user", user.id);
      return user;
    });
    const bootstrap = randomToken();
    await redis.set(
      "bootstrap:" + u.id,
      hash(bootstrap).toString("hex"),
      "EX",
      900,
    );
    writeFileSync(
      ".secrets/admin-bootstrap.json",
      JSON.stringify(
        { login: name, password: pass, bootstrap, user_id: u.id },
        null,
        2,
      ),
      { mode: 0o600 },
    );
    console.log(
      "Administrator created. One-time credentials: .secrets/admin-bootstrap.json (15-minute MFA enrollment).",
    );
  } else if (command === "mfa-bootstrap") {
    const u = await db.user.findUniqueOrThrow({
      where: { login: login.parse(args[0]) },
    });
    if (u.role !== "ADMIN") throw Error("Not admin");
    const bootstrap = randomToken();
    await redis.set(
      "bootstrap:" + u.id,
      hash(bootstrap).toString("hex"),
      "EX",
      900,
    );
    writeFileSync(
      ".secrets/mfa-bootstrap.json",
      JSON.stringify({ bootstrap }),
      { mode: 0o600 },
    );
    await transaction((tx) => audit(tx, u.id, "MfaBootstrap", "user", u.id));
    console.log("Enrollment token saved in .secrets/mfa-bootstrap.json");
  } else if (command === "product") {
    const slug = args[0];
    if (!/^[a-z0-9-]{3,64}$/.test(slug || "")) throw Error("Invalid slug");
    const p = await transaction(async (tx) => {
      const p = await tx.product.create({
        data: {
          id: uuid(),
          slug,
          name: args[1] || slug,
          offlineEnabled: args.includes("--offline"),
        },
      });
      await audit(tx, null, "ProductCreated", "product", p.id);
      return p;
    });
    console.log(`Product ${p.id}`);
  } else
    throw Error(
      "Usage: npm run admin -- create LOGIN | mfa-bootstrap LOGIN | product SLUG NAME [--offline]",
    );
}
main()
  .catch((e) => {
    console.error(
      e instanceof Error && e.message.startsWith("Usage:")
        ? e.message
        : "Operation failed",
    );
    process.exitCode = 1;
  })
  .finally(async () => {
    await db.$disconnect();
    redis.disconnect();
  });
