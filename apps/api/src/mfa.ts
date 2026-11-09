import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { config } from "./config";
import { redis } from "./security";
import { db, audit, transaction } from "./database";
import { Failure } from "./errors";
import { randomToken, hash } from "../../../packages/crypto-server/src/index";
export async function challenge(sid: string, userId: string, enroll: boolean) {
  const user = await db.user.findUniqueOrThrow({ where: { id: userId } });
  if (user.role !== "ADMIN") throw new Failure("FORBIDDEN", 403);
  const creds = await db.credential.findMany({ where: { userId } });
  const options = enroll
    ? await generateRegistrationOptions({
        rpName: "OnlineKeyGen",
        rpID: config.rpId,
        userName: user.login,
        userID: new TextEncoder().encode(user.id),
        attestationType: "none",
        authenticatorSelection: {
          userVerification: "required",
          residentKey: "preferred",
        },
        excludeCredentials: creds.map((c) => ({ id: c.id })),
      })
    : await generateAuthenticationOptions({
        rpID: config.rpId,
        userVerification: "required",
        allowCredentials: creds.map((c) => ({ id: c.id })),
      });
  await redis.set(
    `mfa:${sid}:${enroll ? "enroll" : "auth"}`,
    options.challenge,
    "EX",
    300,
  );
  return options;
}
export async function enrollAuthorization(
  userId: string,
  sid: string,
  bootstrap: unknown,
) {
  const s = await db.webSession.findUniqueOrThrow({ where: { id: sid } });
  if (s.mfaAt && Date.now() - +s.mfaAt < 300000) return;
  if (typeof bootstrap !== "string" || bootstrap.length !== 43)
    throw new Failure("MFA_REQUIRED", 403);
  const key = "bootstrap:" + userId;
  const expected = await redis.get(key);
  if (expected !== hash(bootstrap).toString("hex"))
    throw new Failure("MFA_REQUIRED", 403);
}
export async function verifyMfa(
  sid: string,
  userId: string,
  input: unknown,
  enroll: boolean,
) {
  const key = `mfa:${sid}:${enroll ? "enroll" : "auth"}`;
  const expectedChallenge = await redis.getdel(key);
  if (!expectedChallenge) throw new Failure("INVALID_CHALLENGE", 400);
  try {
    if (enroll) {
      const result = await verifyRegistrationResponse({
        response: input as RegistrationResponseJSON,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpId,
        requireUserVerification: true,
      });
      if (!result.verified || !result.registrationInfo) throw Error();
      const c = result.registrationInfo.credential;
      await transaction(async (tx) => {
        await tx.credential.create({
          data: {
            id: c.id,
            userId,
            publicKey: Buffer.from(c.publicKey),
            counter: BigInt(c.counter),
            transports: c.transports || [],
          },
        });
        await tx.webSession.update({
          where: { id: sid },
          data: { mfaAt: new Date() },
        });
        await audit(tx, userId, "MfaEnrolled", "user", userId);
      });
      await redis.del("bootstrap:" + userId);
    } else {
      const response = input as AuthenticationResponseJSON;
      const c = await db.credential.findUnique({ where: { id: response.id } });
      if (!c || c.userId !== userId) throw Error();
      const result = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpId,
        requireUserVerification: true,
        credential: {
          id: c.id,
          publicKey: new Uint8Array(c.publicKey),
          counter: Number(c.counter),
        },
      });
      if (!result.verified) throw Error();
      await transaction(async (tx) => {
        const count = await tx.credential.updateMany({
          where: { id: c.id, counter: c.counter },
          data: { counter: BigInt(result.authenticationInfo.newCounter) },
        });
        if (count.count !== 1) throw new Failure("INVALID_CHALLENGE");
        await tx.webSession.update({
          where: { id: sid },
          data: { mfaAt: new Date() },
        });
        await audit(tx, userId, "MfaVerified", "session", sid);
      });
    }
  } catch (e) {
    if (e instanceof Failure) throw e;
    throw new Failure("INVALID_CHALLENGE", 400);
  }
  return { success: true };
}
