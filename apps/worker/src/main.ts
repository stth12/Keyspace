import { appendFileSync, mkdirSync } from "node:fs";
import { db, transaction, audit } from "../../api/src/database";
let stopping = false;
async function tick() {
  await transaction(async (tx) => {
    const expired = await tx.$queryRaw<
      { id: string }[]
    >`SELECT id FROM licenses WHERE status='ACTIVE' AND "expiresAt"<=clock_timestamp() ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 100`;
    for (const l of expired) {
      await tx.license.update({
        where: { id: l.id },
        data: { status: "EXPIRED", version: { increment: 1 } },
      });
      await tx.appSession.updateMany({
        where: { licenseId: l.id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await audit(tx, null, "LicenseExpired", "license", l.id);
    }
  });
  for (let batch = 0; batch < 20 && !stopping; batch++) {
    const delivered = await transaction(async (tx) => {
      const events = await tx.$queryRaw<
        { id: string; payload: unknown }[]
      >`SELECT id,payload FROM outbox_events WHERE "deliveredAt" IS NULL ORDER BY "createdAt" FOR UPDATE SKIP LOCKED LIMIT 1`;
      if (events.length === 0) return false;
      for (const event of events) {
        const sink = process.env.AUDIT_SINK_URL;
        if (sink) {
          const r = await fetch(sink, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": event.id,
              ...(process.env.AUDIT_SINK_TOKEN
                ? { Authorization: "Bearer " + process.env.AUDIT_SINK_TOKEN }
                : {}),
            },
            body: JSON.stringify(event.payload),
            signal: AbortSignal.timeout(3000),
            redirect: "error",
          });
          if (!r.ok) throw Error("Audit sink unavailable");
        } else if (process.env.NODE_ENV === "production") {
          throw Error("Production requires external audit sink");
        } else {
          mkdirSync("artifacts", { recursive: true });
          appendFileSync(
            "artifacts/audit-export.jsonl",
            JSON.stringify(event.payload) + "\n",
          );
        }
        await tx.outbox.update({
          where: { id: event.id },
          data: { deliveredAt: new Date(), attempts: { increment: 1 } },
        });
      }
      return true;
    });
    if (!delivered) break;
  }
}
async function main() {
  while (!stopping) {
    try {
      await tick();
    } catch {
      console.error(
        "Worker cycle failed; will retry without discarding events",
      );
    }
    await new Promise((r) => setTimeout(r, 5000));
  }
  await db.$disconnect();
}
process.on("SIGTERM", () => (stopping = true));
process.on("SIGINT", () => (stopping = true));
main();
