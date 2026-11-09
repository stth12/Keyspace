import { createApp } from "./app";
import { config } from "./config";
import { db } from "./database";
import { redis } from "./security";
async function main() {
  const { app } = await createApp();
  await app.listen(config.port, config.host);
  console.log(`API listening on port ${config.port}`);
  const stop = async () => {
    await app.close();
    await db.$disconnect();
    redis.disconnect();
    process.exit(0);
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
main().catch(() => {
  console.error("API startup failed; verify configuration and dependencies");
  process.exit(1);
});
