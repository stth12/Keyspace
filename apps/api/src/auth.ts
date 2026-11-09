import { Request, Response } from "express";
import argon2 from "argon2";
import { SignJWT, jwtVerify } from "jose";
import { v7 as uuid } from "uuid";
import { db, transaction, audit, Tx, dbTime } from "./database";
import { config } from "./config";
import { Failure } from "./errors";
import { origin, limit } from "./security";
import {
  randomToken,
  hash,
  equal,
} from "../../../packages/crypto-server/src/index";
import {
  loginSchema,
  registerSchema,
} from "../../../packages/contracts/src/index";
const DAY = 86400000;
const cookieNames = config.production
  ? { access: "__Host-web_access", refresh: "__Host-web_refresh" }
  : { access: "web_access", refresh: "web_refresh" };
const options = {
  httpOnly: true,
  secure: config.production,
  sameSite: "lax" as const,
  path: "/",
};
const hashOptions = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
};
const dummy = argon2.hash(randomToken(), hashOptions);
let hashing = 0;
export async function passwordWork<T>(fn: () => Promise<T>) {
  if (hashing >= 4) throw new Failure("SERVICE_UNAVAILABLE", 503);
  hashing++;
  try {
    return await fn();
  } finally {
    hashing--;
  }
}
export const passwordHash = (s: string) =>
  passwordWork(() => argon2.hash(s, hashOptions));
export async function register(input: unknown) {
  const b = registerSchema.parse(input);
  const ph = await passwordHash(b.password);
  try {
    await transaction(async (tx) => {
      const u = await tx.user.create({
        data: { id: uuid(), login: b.login, passwordHash: ph },
      });
      await audit(tx, u.id, "Registration", "user", u.id);
    });
  } catch (e) {
    if ((e as { code?: string }).code !== "P2002") throw e;
  }
  return {
    message:
      "Если регистрация доступна, аккаунт создан. Войдите с выбранными данными.",
  };
}
async function access(sid: string, userId: string, version: number) {
  return new SignJWT({ sid, ver: version })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(config.issuer)
    .setAudience("web-api")
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(config.jwt);
}
export function setCookies(
  res: Response,
  token: string,
  refresh: string,
  ttl: number,
) {
  res.cookie(cookieNames.access, token, { ...options, maxAge: 300000 });
  res.cookie(cookieNames.refresh, refresh, { ...options, maxAge: ttl });
}
export function clearCookies(res: Response) {
  res.clearCookie(cookieNames.access, options);
  res.clearCookie(cookieNames.refresh, options);
}
export const userDto = (u: {
  id: string;
  login: string;
  role: string;
  status: string;
  createdAt: Date;
}) => ({
  id: u.id,
  login: u.login,
  role: u.role,
  status: u.status,
  created_at: u.createdAt,
});
export async function login(input: unknown, res: Response) {
  const b = loginSchema.parse(input);
  await limit("login-account", b.login, 10, 900);
  const u = await db.user.findUnique({ where: { login: b.login } });
  const ok = await passwordWork(() =>
    argon2.verify(u?.passwordHash || awaitDummy(), b.password),
  );
  if (!ok || !u || u.status !== "ACTIVE") {
    await transaction((tx) => audit(tx, null, "LoginFailure", "auth", null));
    throw new Failure("INVALID_CREDENTIALS", 401);
  }
  const refresh = randomToken(),
    csrf = randomToken();
  const session = await transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM users WHERE id=${u.id}::uuid FOR SHARE`;
    const current = await tx.user.findUniqueOrThrow({ where: { id: u.id } });
    if (current.status !== "ACTIVE" || current.authVersion !== u.authVersion)
      throw new Failure("INVALID_CREDENTIALS", 401);
    const now = await dbTime(tx);
    const absolute = new Date(
        +now + (u.role === "ADMIN" ? 12 * 3600000 : 30 * DAY),
      ),
      idle = new Date(+now + (u.role === "ADMIN" ? 1800000 : 7 * DAY));
    const s = await tx.webSession.create({
      data: {
        id: uuid(),
        userId: u.id,
        authVersion: u.authVersion,
        csrfHash: hash(csrf),
        absoluteExpiresAt: absolute,
        idleExpiresAt: idle,
      },
    });
    await tx.refreshToken.create({
      data: {
        id: uuid(),
        tokenHash: hash(refresh),
        webSessionId: s.id,
        expiresAt: idle,
      },
    });
    await audit(tx, u.id, "LoginSuccess", "session", s.id);
    return s;
  });
  setCookies(
    res,
    await access(session.id, u.id, u.authVersion),
    refresh,
    +session.idleExpiresAt - Date.now(),
  );
  return { user: userDto(u), csrf_token: csrf };
}
let dummyHash = "";
dummy.then((v) => (dummyHash = v));
function awaitDummy() {
  if (!dummyHash) throw new Failure("SERVICE_UNAVAILABLE", 503);
  return dummyHash;
}
export async function webAuth(req: Request, mutation = false, admin = false) {
  let p;
  try {
    p = (
      await jwtVerify(req.cookies?.[cookieNames.access] || "", config.jwt, {
        algorithms: ["HS256"],
        issuer: config.issuer,
        audience: "web-api",
      })
    ).payload;
  } catch {
    throw new Failure("INVALID_SESSION", 401);
  }
  if (typeof p.sid !== "string") throw new Failure("INVALID_SESSION", 401);
  const s = await db.webSession.findUnique({
    where: { id: p.sid },
    include: { user: true },
  });
  if (
    !s ||
    s.revokedAt ||
    +s.absoluteExpiresAt <= Date.now() ||
    +s.idleExpiresAt <= Date.now() ||
    s.user.status !== "ACTIVE" ||
    s.authVersion !== s.user.authVersion ||
    p.sub !== s.userId ||
    p.ver !== s.authVersion
  )
    throw new Failure("INVALID_SESSION", 401);
  if (mutation) {
    origin(req);
    checkCsrf(req, s.csrfHash);
  }
  if (admin) {
    if (s.user.role !== "ADMIN") throw new Failure("FORBIDDEN", 403);
    if (!s.mfaAt || Date.now() - +s.mfaAt > (mutation ? 300000 : 900000))
      throw new Failure("MFA_REQUIRED", 403);
    await limit("admin-actor", s.userId, mutation ? 30 : 120, 60);
  }
  return s;
}
export function checkCsrf(req: Request, digest: Uint8Array) {
  const c = req.headers["x-csrf-token"];
  if (typeof c !== "string" || c.length > 100 || !equal(hash(c), digest))
    throw new Failure("CSRF_REJECTED", 403);
}
export async function csrfSession(req: Request) {
  const raw = req.cookies?.[cookieNames.refresh];
  if (typeof raw !== "string" || raw.length !== 43)
    throw new Failure("INVALID_SESSION", 401);
  const r = await db.refreshToken.findUnique({
    where: { tokenHash: hash(raw) },
    include: { webSession: { include: { user: true } } },
  });
  const s = r?.webSession;
  if (
    !r ||
    r.consumedAt ||
    r.revokedAt ||
    +r.expiresAt <= Date.now() ||
    !s ||
    s.revokedAt ||
    s.user.status !== "ACTIVE" ||
    s.authVersion !== s.user.authVersion ||
    +s.absoluteExpiresAt <= Date.now() ||
    +s.idleExpiresAt <= Date.now()
  )
    throw new Failure("INVALID_SESSION", 401);
  return { r, s };
}
export async function revokeFamily(tx: Tx, id: string, kind: "web" | "app") {
  const now = new Date();
  if (kind === "web") {
    await tx.webSession.update({ where: { id }, data: { revokedAt: now } });
    await tx.refreshToken.updateMany({
      where: { webSessionId: id },
      data: { revokedAt: now },
    });
  } else {
    await tx.appSession.update({ where: { id }, data: { revokedAt: now } });
    await tx.refreshToken.updateMany({
      where: { appSessionId: id },
      data: { revokedAt: now },
    });
  }
}
export async function webRefresh(req: Request, res: Response) {
  origin(req);
  const raw = req.cookies?.[cookieNames.refresh];
  if (typeof raw !== "string" || raw.length !== 43)
    throw new Failure("INVALID_SESSION", 401);
  const found = await db.refreshToken.findUnique({
    where: { tokenHash: hash(raw) },
  });
  if (!found?.webSessionId) throw new Failure("INVALID_SESSION", 401);
  const fresh = randomToken(),
    csrf = String(req.headers["x-csrf-token"] || "");
  const result = await transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM web_sessions WHERE id=${found.webSessionId}::uuid FOR UPDATE`;
    const r = await tx.refreshToken.findUniqueOrThrow({
      where: { id: found.id },
    });
    const s = await tx.webSession.findUniqueOrThrow({
      where: { id: found.webSessionId! },
      include: { user: true },
    });
    checkCsrf(req, s.csrfHash);
    if (r.consumedAt || r.revokedAt) {
      await revokeFamily(tx, s.id, "web");
      await audit(tx, s.userId, "RefreshReuse", "session", s.id);
      await tx.securityEvent.create({
        data: {
          id: uuid(),
          type: "REFRESH_REUSE",
          metadata: { session_id: s.id },
        },
      });
      return null;
    }
    if (
      s.revokedAt ||
      s.user.status !== "ACTIVE" ||
      s.authVersion !== s.user.authVersion ||
      +r.expiresAt <= Date.now() ||
      +s.absoluteExpiresAt <= Date.now() ||
      +s.idleExpiresAt <= Date.now()
    )
      throw new Failure("INVALID_SESSION", 401);
    await limit("refresh-session", s.id, 10, 60);
    const idle = new Date(
      Math.min(
        +s.absoluteExpiresAt,
        Date.now() + (s.user.role === "ADMIN" ? 1800000 : 7 * DAY),
      ),
    );
    await tx.refreshToken.update({
      where: { id: r.id },
      data: { consumedAt: new Date() },
    });
    await tx.refreshToken.create({
      data: {
        id: uuid(),
        parentId: r.id,
        tokenHash: hash(fresh),
        webSessionId: s.id,
        expiresAt: idle,
      },
    });
    await tx.webSession.update({
      where: { id: s.id },
      data: { idleExpiresAt: idle, csrfHash: hash(csrf) },
    });
    return { ...s, idleExpiresAt: idle };
  });
  if (!result) {
    clearCookies(res);
    throw new Failure("INVALID_SESSION", 401);
  }
  setCookies(
    res,
    await access(result.id, result.userId, result.authVersion),
    fresh,
    +result.idleExpiresAt - Date.now(),
  );
  return { csrf_token: csrf };
}
