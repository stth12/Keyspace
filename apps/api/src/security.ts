import Redis from "ioredis";
import { Request } from "express";
import { config } from "./config";
import { mac } from "../../../packages/crypto-server/src/index";
import { Failure } from "./errors";
import { transaction, audit } from "./database";
import { v7 as uuid } from "uuid";
export const redis = new Redis(config.redis, {
  maxRetriesPerRequest: 1,
  connectTimeout: 3000,
  enableOfflineQueue: false,
});
redis.on("error", () => {});
const script = `local n=redis.call('INCR',KEYS[1]);if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end;return n`;
export async function limit(
  bucket: string,
  value: string,
  max: number,
  seconds: number,
) {
  try {
    const key =
      "rl:" + bucket + ":" + mac(config.fingerprint, value).toString("hex");
    const n = Number(await redis.eval(script, 1, key, seconds));
    if (n === max + 1)
      await transaction(async (tx) => {
        const id = uuid();
        const metadata = {
          bucket,
          fingerprint: key.split(":").at(-1)!,
          window_seconds: seconds,
        };
        await tx.securityEvent.create({
          data: { id, type: "RATE_LIMIT_THRESHOLD", metadata },
        });
        await audit(
          tx,
          null,
          "RateLimitThreshold",
          "security_event",
          id,
          metadata,
        );
      });
    if (n > max) throw new Failure("RATE_LIMITED", 429);
  } catch (e) {
    if (e instanceof Failure) throw e;
    throw new Failure("SERVICE_UNAVAILABLE", 503);
  }
}
export function origin(req: Request) {
  if (req.headers.origin !== config.origin)
    throw new Failure("CSRF_REJECTED", 403);
}
export function sameOriginRead(req: Request) {
  if (
    req.headers.origin === config.origin ||
    req.headers["sec-fetch-site"] === "same-origin"
  )
    return;
  throw new Failure("CSRF_REJECTED", 403);
}
export function bearer(req: Request) {
  const m = /^Bearer ([A-Za-z0-9_.-]{1,8192})$/.exec(
    req.headers.authorization || "",
  );
  if (!m) throw new Failure("INVALID_SESSION", 401);
  return m[1];
}
export async function ipLimit(
  req: Request,
  bucket: string,
  max: number,
  seconds: number,
) {
  await limit(bucket, req.ip || "unknown", max, seconds);
}
