import {
  Controller,
  Get,
  Post,
  Patch,
  Put,
  Body,
  Req,
  Res,
  Param,
  Query,
  HttpCode,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiBody,
  ApiBearerAuth,
  ApiCookieAuth,
  ApiResponse,
} from "@nestjs/swagger";
import { Request, Response } from "express";
import { z } from "zod";
import { v7 as newId } from "uuid";
import argon2 from "argon2";
import { db, transaction, audit, lockLicense } from "./database";
import { config, keyStore } from "./config";
import { Failure } from "./errors";
import { ipLimit, origin, sameOriginRead, bearer, redis } from "./security";
import * as auth from "./auth";
import * as licenses from "./licenses";
import * as mfa from "./mfa";
import {
  uuid,
  registerSchema,
  loginSchema,
  activateSchema,
  scopeSchema,
  refreshSchema,
  issueSchema,
  selfIssueSchema,
  patchSchema,
  mutationSchema,
  entitlementSchema,
  password,
} from "../../../packages/contracts/src/index";
import { hash, randomToken } from "../../../packages/crypto-server/src/index";
const schema = (s: z.ZodType) => ({
  schema: z.toJSONSchema(s, { io: "input" }) as never,
});
const pageSchema = z
  .object({
    cursor: uuid.optional(),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    search: z.string().max(32).optional(),
    status: z
      .enum(["ACTIVE", "BLOCKED", "NOT_ACTIVATED", "EXPIRED", "REVOKED"])
      .optional(),
    product_id: uuid.optional(),
    user_id: uuid.optional(),
  })
  .strict();
@ApiTags("Licensing v1")
@ApiResponse({ status: 400, description: "INVALID_REQUEST / invalid DTO" })
@ApiResponse({
  status: 401,
  description: "INVALID_SESSION / INVALID_LICENSE / INVALID_CREDENTIALS",
})
@ApiResponse({
  status: 403,
  description: "FORBIDDEN / MFA_REQUIRED / CSRF_REJECTED / license denied",
})
@ApiResponse({ status: 429, description: "RATE_LIMITED" })
@Controller("api/v1")
export class ApiController {
  @Get("health/live") live() {
    return { status: "ok" };
  }
  @Get("health/ready") async ready() {
    await db.$queryRaw`SELECT 1`;
    await redis.ping();
    return { status: "ready" };
  }
  @Post("auth/register")
  @HttpCode(202)
  @ApiBody(schema(registerSchema))
  async register(@Req() req: Request, @Body() body: unknown) {
    origin(req);
    await ipLimit(req, "register", 5, 3600);
    return auth.register(body);
  }
  @Post("auth/login") @HttpCode(200) @ApiBody(schema(loginSchema)) async login(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() body: unknown,
  ) {
    origin(req);
    await ipLimit(req, "login", 20, 300);
    return auth.login(body, res);
  }
  @Post("auth/refresh") @HttpCode(200) @ApiCookieAuth() async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    await ipLimit(req, "refresh", 60, 60);
    return auth.webRefresh(req, res);
  }
  @Post("auth/logout") @HttpCode(204) @ApiCookieAuth() async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const s = await auth.webAuth(req, true);
    await transaction(async (tx) => {
      await auth.revokeFamily(tx, s.id, "web");
      await audit(tx, s.userId, "Logout", "session", s.id);
    });
    auth.clearCookies(res);
  }
  @Get("auth/me") @ApiCookieAuth() async me(@Req() req: Request) {
    const s = await auth.webAuth(req);
    return { ...auth.userDto(s.user), mfa_verified_at: s.mfaAt };
  }
  @Get("auth/csrf") @ApiCookieAuth() async csrf(@Req() req: Request) {
    sameOriginRead(req);
    const { s } = await auth.csrfSession(req);
    const token = randomToken();
    await db.webSession.update({
      where: { id: s.id },
      data: { csrfHash: hash(token) },
    });
    return { csrf_token: token };
  }
  @Post("auth/password") @HttpCode(204) @ApiCookieAuth() async password(
    @Req() req: Request,
    @Body() input: unknown,
  ) {
    const s = await auth.webAuth(req, true);
    const b = z
      .object({
        current_password: z.string().max(128),
        new_password: password,
        confirm_password: password,
      })
      .strict()
      .refine((v) => v.new_password === v.confirm_password)
      .parse(input);
    if (
      !(await auth.passwordWork(() =>
        argon2.verify(s.user.passwordHash, b.current_password),
      ))
    )
      throw new Failure("INVALID_CREDENTIALS", 401);
    const next = await auth.passwordHash(b.new_password);
    await transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM users WHERE id=${s.userId}::uuid FOR UPDATE`;
      await tx.user.update({
        where: { id: s.userId },
        data: { passwordHash: next, authVersion: { increment: 1 } },
      });
      await tx.webSession.updateMany({
        where: { userId: s.userId },
        data: { revokedAt: new Date() },
      });
      await audit(tx, s.userId, "PasswordChanged", "user", s.userId);
    });
  }
  @Post("auth/mfa/challenge") @ApiCookieAuth() async challenge(
    @Req() req: Request,
  ) {
    const s = await auth.webAuth(req, true);
    return mfa.challenge(s.id, s.userId, false);
  }
  @Post("auth/mfa/verify") @ApiCookieAuth() async verify(
    @Req() req: Request,
    @Body() b: unknown,
  ) {
    const s = await auth.webAuth(req, true);
    return mfa.verifyMfa(s.id, s.userId, b, false);
  }
  @Post("auth/mfa/enroll/challenge") @ApiCookieAuth() async enrollChallenge(
    @Req() req: Request,
    @Body() input: unknown,
  ) {
    const s = await auth.webAuth(req, true);
    const b = z
      .object({ bootstrap: z.string().max(100).optional() })
      .strict()
      .parse(input);
    await mfa.enrollAuthorization(s.userId, s.id, b.bootstrap);
    return mfa.challenge(s.id, s.userId, true);
  }
  @Post("auth/mfa/enroll/verify") @ApiCookieAuth() async enrollVerify(
    @Req() req: Request,
    @Body() input: unknown,
  ) {
    const s = await auth.webAuth(req, true);
    const b = z
      .object({
        bootstrap: z.string().max(100).optional(),
        response: z.unknown(),
      })
      .strict()
      .parse(input);
    await mfa.enrollAuthorization(s.userId, s.id, b.bootstrap);
    return mfa.verifyMfa(s.id, s.userId, b.response, true);
  }
  @Get("products") @ApiCookieAuth() async products(@Req() req: Request) {
    const s = await auth.webAuth(req);
    return db.product.findMany({
      where: { enabled: true },
      select: {
        id: true,
        name: true,
        slug: true,
        offlineEnabled: true,
        entitlements: {
          where: { userId: s.userId },
          select: {
            remaining: true,
            durations: true,
            lifetime: true,
                  maxDevices: true,
                  expiresAt: true,
          },
        },
      },
    });
  }
  @Get("licenses") @ApiCookieAuth() async list(
    @Req() req: Request,
    @Query() q: unknown,
  ) {
    const s = await auth.webAuth(req);
    return this.licenseList(q, s.userId);
  }
  @Post("licenses")
  @ApiCookieAuth()
  @ApiBody(schema(selfIssueSchema))
  async issue(@Req() req: Request, @Body() b: unknown) {
    const s = await auth.webAuth(req, true);
    return licenses.issue(
      s.userId,
      b,
      false,
      uuid.parse(req.headers["idempotency-key"]),
    );
  }
  @Post("licenses/activate")
  @HttpCode(200)
  @ApiBody(schema(activateSchema))
  async activate(@Req() req: Request, @Body() b: unknown) {
    await ipLimit(req, "activate", 30, 300);
    return licenses.activate(b);
  }
  @Post("licenses/validate")
  @HttpCode(200)
  @ApiBearerAuth()
  @ApiBody(schema(scopeSchema))
  async validate(@Req() req: Request, @Body() b: unknown) {
    await ipLimit(req, "validate", 600, 60);
    return licenses.validate(bearer(req), b);
  }
  @Post("licenses/offline-token")
  @HttpCode(200)
  @ApiBearerAuth()
  @ApiBody(schema(scopeSchema))
  async offline(@Req() req: Request, @Body() b: unknown) {
    await ipLimit(req, "offline", 30, 3600);
    return licenses.offline(bearer(req), b);
  }
  @Post("application-sessions/refresh")
  @HttpCode(200)
  @ApiBody(schema(refreshSchema))
  async appRefresh(@Req() req: Request, @Body() b: unknown) {
    await ipLimit(req, "app-refresh", 60, 60);
    return licenses.appRefresh(b);
  }
  @Post("application-sessions/logout")
  @HttpCode(204)
  @ApiBearerAuth()
  async appLogout(@Req() req: Request, @Body() b: unknown) {
    await transaction(async (tx) => {
      const { s } = await licenses.appContext(tx, bearer(req), b);
      await auth.revokeFamily(tx, s.id, "app");
      await audit(tx, s.userId, "Logout", "session", s.id);
    });
  }
  @Get("licenses/:id") @ApiCookieAuth() async detail(
    @Req() req: Request,
    @Param("id") id: string,
  ) {
    const s = await auth.webAuth(req);
    const l = await db.license.findFirst({
      where: { id: uuid.parse(id), userId: s.userId },
      include: { product: true, activations: true },
    });
    if (!l) throw new Failure("NOT_FOUND", 404);
    return licenses.licenseDto(l);
  }
  @Get("signing-keys/manifest") manifest() {
    return keyStore.manifest;
  }
  @Get("admin/statistics") @ApiCookieAuth() async stats(@Req() req: Request) {
    await auth.webAuth(req, false, true);
    const counts = await db.$queryRaw<
      { status: string; count: bigint }[]
    >`SELECT CASE WHEN status='ACTIVE' AND "expiresAt"<=clock_timestamp() THEN 'EXPIRED' ELSE status::text END AS status, count(*) AS count FROM licenses GROUP BY 1`;
    return {
      total_users: await db.user.count(),
      total_licenses: await db.license.count(),
      lifetime: await db.license.count({ where: { isLifetime: true } }),
      statuses: Object.fromEntries(
        counts.map((c) => [c.status, Number(c.count)]),
      ),
    };
  }
  @Get("admin/users") @ApiCookieAuth() async users(
    @Req() req: Request,
    @Query() q: unknown,
  ) {
    await auth.webAuth(req, false, true);
    const p = pageSchema.parse(q);
    const rows = await db.user.findMany({
      where: {
        login: p.search ? { startsWith: p.search.toLowerCase() } : undefined,
        status:
          p.status === "ACTIVE" || p.status === "BLOCKED"
            ? p.status
            : undefined,
        id: p.cursor ? { gt: p.cursor } : undefined,
      },
      orderBy: { id: "asc" },
      take: p.limit + 1,
      select: {
        id: true,
        login: true,
        role: true,
        status: true,
        authVersion: true,
        createdAt: true,
        _count: { select: { licenses: true } },
      },
    });
    return {
      items: rows.slice(0, p.limit),
      next_cursor: rows.length > p.limit ? rows[p.limit - 1].id : null,
    };
  }
  @Get("admin/users/:id") @ApiCookieAuth() async user(
    @Req() req: Request,
    @Param("id") id: string,
  ) {
    await auth.webAuth(req, false, true);
    const u = await db.user.findUnique({ where: { id: uuid.parse(id) } });
    if (!u) throw new Failure("NOT_FOUND", 404);
    return auth.userDto(u);
  }
  @Post("admin/users/:id/:action") @ApiCookieAuth() async blockUser(
    @Req() req: Request,
    @Param("id") id: string,
    @Param("action") action: string,
    @Body() input: unknown,
  ) {
    const s = await auth.webAuth(req, true, true);
    uuid.parse(id);
    if (!["block", "unblock"].includes(action))
      throw new Failure("NOT_FOUND", 404);
    const b = mutationSchema.parse(input);
    return transaction(async (tx) => {
      await tx.$queryRaw`SELECT pg_advisory_xact_lock(937105)::text`;
      await tx.$queryRaw`SELECT id FROM users WHERE id=${id}::uuid FOR UPDATE`;
      const u = await tx.user.findUniqueOrThrow({ where: { id } });
      if (u.authVersion !== b.expected_version)
        throw new Failure("VERSION_CONFLICT", 409);
      if (
        action === "block" &&
        u.role === "ADMIN" &&
        (await tx.user.count({ where: { role: "ADMIN", status: "ACTIVE" } })) <=
          1
      )
        throw new Failure("LAST_ADMIN", 409);
      const updated = await tx.user.update({
        where: { id },
        data: {
          status: action === "block" ? "BLOCKED" : "ACTIVE",
          authVersion: { increment: 1 },
        },
      });
      await tx.webSession.updateMany({
        where: { userId: id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await tx.appSession.updateMany({
        where: { userId: id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await audit(tx, s.userId, "User" + action, "user", id, {
        reason: b.reason,
      });
      return auth.userDto(updated);
    });
  }
  @Get("admin/licenses") @ApiCookieAuth() async adminLicenses(
    @Req() req: Request,
    @Query() q: unknown,
  ) {
    await auth.webAuth(req, false, true);
    return this.licenseList(q);
  }
  @Get("admin/licenses/:id") @ApiCookieAuth() async adminLicense(
    @Req() req: Request,
    @Param("id") id: string,
  ) {
    await auth.webAuth(req, false, true);
    const l = await db.license.findUnique({
      where: { id: uuid.parse(id) },
      include: { owner: true, product: true, activations: true },
    });
    if (!l) throw new Failure("NOT_FOUND", 404);
    return licenses.licenseDto(l);
  }
  @Post("admin/licenses")
  @ApiCookieAuth()
  @ApiBody(schema(issueSchema))
  async adminIssue(@Req() req: Request, @Body() b: unknown) {
    const s = await auth.webAuth(req, true, true);
    const parsed = issueSchema.parse(b);
    if (!parsed.reason || !parsed.user_id) throw new Failure("INVALID_REQUEST");
    return licenses.issue(
      s.userId,
      parsed,
      true,
      uuid.parse(req.headers["idempotency-key"]),
    );
  }
  @Post("admin/licenses/:id/:action")
  @ApiCookieAuth()
  @ApiBody(schema(mutationSchema))
  async licenseAction(
    @Req() req: Request,
    @Param("id") id: string,
    @Param("action") action: string,
    @Body() b: unknown,
  ) {
    const s = await auth.webAuth(req, true, true);
    if (!["revoke", "block", "unblock"].includes(action))
      throw new Failure("NOT_FOUND", 404);
    mutationSchema.parse(b);
    return licenses.mutateLicense(s.userId, uuid.parse(id), action, b);
  }
  @Patch("admin/licenses/:id")
  @ApiCookieAuth()
  @ApiBody(schema(patchSchema))
  async patch(
    @Req() req: Request,
    @Param("id") id: string,
    @Body() b: unknown,
  ) {
    const s = await auth.webAuth(req, true, true);
    return licenses.mutateLicense(s.userId, uuid.parse(id), "patch", b);
  }
  @Post("admin/licenses/:id/devices/:device/:action")
  @ApiCookieAuth()
  async device(
    @Req() req: Request,
    @Param("id") id: string,
    @Param("device") device: string,
    @Param("action") action: string,
    @Body() input: unknown,
  ) {
    const s = await auth.webAuth(req, true, true);
    uuid.parse(id);
    uuid.parse(device);
    if (!["revoke", "restore"].includes(action))
      throw new Failure("NOT_FOUND", 404);
    const b = z
      .object({ reason: z.string().min(3).max(500) })
      .strict()
      .parse(input);
    return transaction(async (tx) => {
      const l = await lockLicense(tx, id);
      if (!l) throw new Failure("NOT_FOUND", 404);
      const d = await tx.activation.findUnique({
        where: { licenseId_deviceId: { licenseId: id, deviceId: device } },
      });
      if (!d) throw new Failure("NOT_FOUND", 404);
      if (
        action === "restore" &&
        d.revokedAt &&
        l.maxDevices !== null &&
        (await tx.activation.count({
          where: { licenseId: id, revokedAt: null },
        })) >= l.maxDevices
      )
        throw new Failure("DEVICE_LIMIT_REACHED", 409);
      await tx.activation.update({
        where: { id: d.id },
        data: { revokedAt: action === "revoke" ? new Date() : null },
      });
      await tx.appSession.updateMany({
        where: { licenseId: id, deviceId: device },
        data: { revokedAt: new Date() },
      });
      await audit(tx, s.userId, "Device" + action, "license", id, {
        device_id: device,
        reason: b.reason,
      });
      return { success: true };
    });
  }
  @Put("admin/users/:id/entitlements/:product")
  @ApiCookieAuth()
  @ApiBody(schema(entitlementSchema))
  async entitlement(
    @Req() req: Request,
    @Param("id") id: string,
    @Param("product") product: string,
    @Body() input: unknown,
  ) {
    const s = await auth.webAuth(req, true, true);
    const b = entitlementSchema.parse(input);
    uuid.parse(id);
    uuid.parse(product);
    return transaction(async (tx) => {
      const data = {
        remaining: b.remaining,
        durations: b.durations,
        lifetime: b.lifetime,
        maxDevices: b.max_devices,
      };
      const e = await tx.entitlement.upsert({
        where: { userId_productId: { userId: id, productId: product } },
        create: { id: newId(), userId: id, productId: product, ...data },
        update: data,
      });
      await audit(tx, s.userId, "EntitlementChanged", "user", id, {
        product_id: product,
        reason: b.reason,
      });
      return e;
    });
  }
  @Get("admin/audit-logs") @ApiCookieAuth() async audit(
    @Req() req: Request,
    @Query() q: unknown,
  ) {
    await auth.webAuth(req, false, true);
    const p = pageSchema.parse(q);
    return db.auditLog.findMany({
      where: { id: p.cursor ? { lt: p.cursor } : undefined },
      orderBy: { id: "desc" },
      take: p.limit,
    });
  }
  @Get("admin/security-events") @ApiCookieAuth() async events(
    @Req() req: Request,
    @Query() q: unknown,
  ) {
    await auth.webAuth(req, false, true);
    const p = pageSchema.parse(q);
    return db.securityEvent.findMany({
      where: { id: p.cursor ? { lt: p.cursor } : undefined },
      orderBy: { id: "desc" },
      take: p.limit,
    });
  }
  private async licenseList(q: unknown, owner?: string) {
    const p = pageSchema.parse(q);
    const now = new Date();
    const filter =
      p.status === "EXPIRED"
        ? {
            OR: [
              { status: "EXPIRED" as const },
              { status: "ACTIVE" as const, expiresAt: { lte: now } },
            ],
          }
        : p.status === "ACTIVE"
          ? {
              status: "ACTIVE" as const,
              OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
            }
          : p.status
            ? { status: p.status }
            : {};
    const rows = await db.license.findMany({
      where: {
        ...filter,
        userId: owner || p.user_id,
        productId: p.product_id,
        id: p.cursor ? { gt: p.cursor } : undefined,
      },
      include: { product: true, owner: true, activations: true },
      orderBy: { id: "asc" },
      take: p.limit + 1,
    });
    return {
      items: rows.slice(0, p.limit).map(licenses.licenseDto),
      next_cursor: rows.length > p.limit ? rows[p.limit - 1].id : null,
    };
  }
}
