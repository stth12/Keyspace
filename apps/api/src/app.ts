import "reflect-metadata";
import { Module } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import { json, Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import { randomUUID } from "node:crypto";
import { ApiController } from "./controller";
import { Errors } from "./errors";
import { config } from "./config";
import { completeContract } from "./openapi";
import { ipLimit } from "./security";
@Module({ controllers: [ApiController] })
export class AppModule {}
export async function createApp() {
  const app = await NestFactory.create(AppModule, {
    bodyParser: false,
    logger: ["warn", "error"],
  });
  if (process.env.TRUST_PROXY)
    app
      .getHttpAdapter()
      .getInstance()
      .set("trust proxy", process.env.TRUST_PROXY);
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader("X-Request-Id", randomUUID());
    res.setHeader("Cache-Control", "no-store");
    if (req.path.startsWith("/api/v1/admin") && req.method !== "GET")
      res.setHeader("Pragma", "no-cache");
    next();
  });
  app.use(helmet());
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (req.path.startsWith("/api/v1/admin"))
        await ipLimit(req, "admin-ip", 120, 60);
      next();
    } catch (e) {
      const limited = e instanceof Error && e.message === "RATE_LIMITED";
      if (limited) res.setHeader("Retry-After", "60");
      res
        .status(limited ? 429 : 503)
        .json({
          error: {
            code: limited ? "RATE_LIMITED" : "SERVICE_UNAVAILABLE",
            message: limited ? "RATE_LIMITED" : "SERVICE_UNAVAILABLE",
            request_id: randomUUID(),
          },
        });
    }
  });
  app.use(json({ limit: "32kb" }));
  app.use(cookieParser());
  app.enableCors({
    origin: config.origin,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "PUT"],
    allowedHeaders: [
      "Content-Type",
      "X-CSRF-Token",
      "Idempotency-Key",
      "Authorization",
    ],
  });
  app.useGlobalFilters(new Errors());
  const doc = SwaggerModule.createDocument(
    app,
    new DocumentBuilder()
      .setTitle("OnlineKeyGen")
      .setVersion("1.0")
      .setDescription(
        "LP1 licensing API. Cookie mutations require Origin and X-CSRF-Token. Admin requires recent WebAuthn.",
      )
      .addBearerAuth()
      .addCookieAuth(config.production ? "__Host-web_access" : "web_access")
      .build(),
  );
  completeContract(doc);
  if (!config.production) SwaggerModule.setup("api/docs", app, doc);
  return { app, doc };
}
