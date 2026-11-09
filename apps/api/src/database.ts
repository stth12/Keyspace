import { PrismaClient, Prisma } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { v7 as uuid } from "uuid";
import "dotenv/config";
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw Error("Missing configuration: DATABASE_URL");
export const db = new PrismaClient({
  adapter: new PrismaPg({
    connectionString: databaseUrl,
    max: 15,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
  }),
});
export type Tx = Prisma.TransactionClient;
export async function transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await db.$transaction(fn, { timeout: 10000, maxWait: 5000 });
    } catch (e) {
      if (
        i < 2 &&
        e instanceof Prisma.PrismaClientKnownRequestError &&
        e.code === "P2034"
      ) {
        await new Promise((r) => setTimeout(r, 25 * (i + 1)));
        continue;
      }
      throw e;
    }
  }
}
export async function audit(
  tx: Tx,
  actor: string | null,
  action: string,
  targetType: string,
  targetId: string | null,
  metadata: Prisma.InputJsonValue = {},
) {
  const id = uuid();
  const payload = {
    id,
    actor_user_id: actor,
    action,
    target_type: targetType,
    target_id: targetId,
    metadata,
  };
  await tx.auditLog.create({
    data: { id, actorUserId: actor, action, targetType, targetId, metadata },
  });
  await tx.outbox.create({ data: { id: uuid(), auditId: id, payload } });
}
export async function dbTime(tx: Tx) {
  const r = await tx.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AS now`;
  return r[0].now;
}
export async function lockLicense(tx: Tx, id: string) {
  const l = await tx.license.findUnique({ where: { id } });
  if (!l) return null;
  await tx.$queryRaw`SELECT id FROM products WHERE id=${l.productId}::uuid FOR SHARE`;
  await tx.$queryRaw`SELECT id FROM users WHERE id=${l.userId}::uuid FOR SHARE`;
  await tx.$queryRaw`SELECT id FROM licenses WHERE id=${id}::uuid FOR UPDATE`;
  return tx.license.findUnique({
    where: { id },
    include: { owner: true, product: true },
  });
}
