import type { OpenAPIObject } from "@nestjs/swagger";
const string = { type: "string" };
const id = { type: "string", format: "uuid" };
const date = { type: "string", format: "date-time", nullable: true };
const object = (
  properties: Record<string, unknown>,
  required = Object.keys(properties),
) => ({ type: "object", properties, required });
export function completeContract(doc: OpenAPIObject) {
  const schemas: Record<string, unknown> = {
    Error: object({
      error: object({ code: string, message: string, request_id: id }),
    }),
    User: object({
      id,
      login: string,
      role: { type: "string", enum: ["USER", "ADMIN"] },
      status: { type: "string", enum: ["ACTIVE", "BLOCKED"] },
      created_at: date,
    }),
    License: object({
      id,
      user_id: id,
      product_id: id,
      masked_key: string,
      status: {
        type: "string",
        enum: ["NOT_ACTIVATED", "ACTIVE", "EXPIRED", "REVOKED", "BLOCKED"],
      },
      duration_seconds: { type: "integer", nullable: true },
      is_lifetime: { type: "boolean" },
      created_at: date,
      activated_at: date,
      expires_at: date,
      max_devices: { type: "integer", nullable: true },
      activation_count: { type: "integer" },
      version: { type: "integer" },
      devices: { type: "array", items: { type: "object" } },
    }),
    SignedSession: object({ token: string, expires_at: date }),
    Refresh: object({ token: string, expires_at: date }),
  };
  const ref = (name: string) => ({ $ref: "#/components/schemas/" + name });
  schemas.Activation = object({
    success: { type: "boolean" },
    user: object({ id, login: string }),
    license: ref("License"),
    session: ref("SignedSession"),
    refresh: ref("Refresh"),
    server_time: date,
  });
  schemas.Validation = object({
    success: { type: "boolean" },
    user: object({ id, login: string }),
    license: ref("License"),
    server_time: date,
    next_validation_after_seconds: { type: "integer" },
  });
  schemas.LicensePage = object({
    items: { type: "array", items: ref("License") },
    next_cursor: { ...id, nullable: true },
  });
  schemas.IssuedLicense = object(
    {
      license: ref("License"),
      license_key: string,
      key_recoverable: { type: "boolean" },
    },
    ["license"],
  );
  schemas.Offline = object({
    token: string,
    valid_until: date,
    server_time: date,
  });
  schemas.SessionRefresh = object({
    session: ref("SignedSession"),
    refresh: ref("Refresh"),
    server_time: date,
  });
  doc.components ||= {};
  doc.components.schemas = { ...doc.components.schemas, ...(schemas as any) };
  const responses: Record<string, string> = {
    "POST /api/v1/licenses/activate": "Activation",
    "POST /api/v1/licenses/validate": "Validation",
    "POST /api/v1/licenses/offline-token": "Offline",
    "POST /api/v1/application-sessions/refresh": "SessionRefresh",
    "GET /api/v1/auth/me": "User",
    "GET /api/v1/licenses": "LicensePage",
    "GET /api/v1/admin/licenses": "LicensePage",
    "POST /api/v1/licenses": "IssuedLicense",
    "POST /api/v1/admin/licenses": "IssuedLicense",
    "GET /api/v1/licenses/{id}": "License",
    "GET /api/v1/admin/licenses/{id}": "License",
    "PATCH /api/v1/admin/licenses/{id}": "License",
  };
  for (const [path, item] of Object.entries(doc.paths)) {
    for (const method of ["get", "post", "put", "patch"] as const) {
      const op = item?.[method];
      if (!op) continue;
      op.responses ||= {};
      for (const code of ["400", "401", "403", "404", "409", "429", "503"])
        op.responses[code] = {
          description:
            code === "429"
              ? "RATE_LIMITED; retry after indicated interval"
              : "Stable error code; no internal exception details",
          content: { "application/json": { schema: ref("Error") } },
        };
      const name = responses[method.toUpperCase() + " " + path];
      if (name) {
        const status =
          Object.keys(op.responses).find((s) => s.startsWith("2")) ||
          (method === "post" ? "201" : "200");
        op.responses[status] = {
          description: "Success",
          content: { "application/json": { schema: ref(name) } },
        };
      }
    }
  }
}
