import { z } from "zod";
export const uuid = z.uuid();
export const login = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9_]{2,31}$/)
  .transform((v) => v.toLowerCase());
export const password = z
  .string()
  .min(15)
  .max(128)
  .refine((v) => Buffer.byteLength(v, "utf8") <= 1024);
export const registerSchema = z
  .object({ login, password, confirm_password: password })
  .strict()
  .refine((v) => v.password === v.confirm_password, {
    path: ["confirm_password"],
    message: "Passwords differ",
  });
export const loginSchema = z
  .object({ login, password: z.string().min(1).max(128) })
  .strict();
export const scopeSchema = z
  .object({ product_id: uuid, device_id: uuid })
  .strict();
export const activateSchema = scopeSchema
  .extend({ license_key: z.string().max(128) })
  .strict();
export const refreshSchema = scopeSchema
  .extend({ refresh_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/) })
  .strict();
export const duration = z.number().int().min(1).max(315360000);
export const issueSchema = z
  .object({
    product_id: uuid,
    duration_seconds: duration.nullable(),
    is_lifetime: z.boolean(),
    max_devices: z.number().int().min(1).max(1000).nullable().default(1),
    user_id: uuid.optional(),
    reason: z.string().min(3).max(500).optional(),
  })
  .strict()
  .refine((v) =>
    v.is_lifetime ? v.duration_seconds === null : v.duration_seconds !== null,
  );
export const selfIssueSchema = z
  .object({
    product_id: uuid,
    duration_seconds: duration.nullable(),
    is_lifetime: z.boolean(),
  })
  .strict()
  .refine((v) =>
    v.is_lifetime ? v.duration_seconds === null : v.duration_seconds !== null,
  );
export const mutationSchema = z
  .object({
    reason: z.string().min(3).max(500),
    expected_version: z.number().int().positive(),
  })
  .strict();
export const patchSchema = mutationSchema
  .extend({
    operation: z.enum([
      "set_unactivated_duration",
      "extend_by_seconds",
      "set_expires_at",
      "set_lifetime",
      "set_max_devices",
    ]),
    duration_seconds: duration.optional(),
    expires_at: z.iso.datetime().optional(),
    max_devices: z.number().int().min(1).max(1000).nullable().optional(),
  })
  .strict();
export const entitlementSchema = z
  .object({
    remaining: z.number().int().min(0).max(100000),
    durations: z.array(duration).max(30),
    lifetime: z.boolean(),
    max_devices: z.number().int().min(1).max(1000).nullable(),
    reason: z.string().min(3).max(500),
  })
  .strict();
export const presets = [
  3600, 43200, 86400, 259200, 604800, 1209600, 2592000, 7776000, 15552000,
  31536000,
];
export const sessionClaims = z
  .object({
    issuer: z.string(),
    audience: z.literal("application-api"),
    session_id: uuid,
    license_id: uuid,
    user_id: uuid,
    product_id: uuid,
    device_id: uuid,
    issued_at: z.number().int().nonnegative(),
    expires_at: z.number().int().positive(),
    license_version: z.number().int().positive(),
    nonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  })
  .strict();
export const offlineClaims = z
  .object({
    version: z.literal(1),
    issuer: z.string(),
    audience: z.literal("offline-license"),
    license_id: uuid,
    user_id: uuid,
    product_id: uuid,
    device_id: uuid,
    issued_at: z.number().int().nonnegative(),
    valid_until: z.number().int().positive(),
    license_expires_at: z.number().int().nullable(),
    lifetime: z.boolean(),
    license_version: z.number().int().positive(),
    nonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  })
  .strict();
