import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
} from "@nestjs/common";
import { Response, Request } from "express";
import { ZodError } from "zod";
import { Prisma } from "@prisma/client";
export class Failure extends Error {
  constructor(
    public code: string,
    public status = 400,
  ) {
    super(code);
  }
}
@Catch()
export class Errors implements ExceptionFilter {
  catch(e: unknown, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse<Response>();
    const request = host.switchToHttp().getRequest<Request>();
    let status = 500,
      code = "INTERNAL_ERROR";
    if (e instanceof Failure) {
      status = e.status;
      code = e.code;
    } else if (e instanceof ZodError) {
      status = 400;
      code = "INVALID_REQUEST";
    } else if (
      e instanceof Prisma.PrismaClientKnownRequestError &&
      ["P2002", "P2003"].includes(e.code)
    ) {
      status = 409;
      code = "CONFLICT";
    } else if (e instanceof HttpException) {
      status = e.getStatus();
      code = status === 404 ? "NOT_FOUND" : "INVALID_REQUEST";
    } else if (
      e &&
      typeof e === "object" &&
      "status" in e &&
      (e.status === 400 || e.status === 413)
    ) {
      status = e.status;
      code = status === 413 ? "PAYLOAD_TOO_LARGE" : "INVALID_REQUEST";
    }
    if (status === 500)
      console.error(
        JSON.stringify({
          event: "request_failed",
          request_id: response.getHeader("X-Request-Id"),
          path: request.path,
          error_type: e instanceof Error ? e.constructor.name : "Unknown",
        }),
      );
    if (status === 429) response.setHeader("Retry-After", "60");
    response.status(status).json({
      error: {
        code,
        message: code,
        request_id: response.getHeader("X-Request-Id"),
      },
    });
  }
}
