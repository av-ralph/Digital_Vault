import { browserLocationSchema } from "./location.js";
import { z } from "zod";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isIP } from "node:net";
export const policySchema = z
  .object({
    ipLimit: z.number().int().min(5).max(1000),
    accountLimit: z.number().int().min(3).max(100),
    rateWindowSeconds: z.number().int().min(10).max(3600),
    lockThreshold: z.number().int().min(3).max(20),
    lockSeconds: z.number().int().min(10).max(3600),
    alertThreshold: z.number().int().min(2).max(50),
    alertWindowSeconds: z.number().int().min(30).max(86400),
    sessionMinutes: z.number().int().min(5).max(1440),
    retentionLimit: z.number().int().min(100).max(50000),
  })
  .strict();
export type Policy = z.infer<typeof policySchema>;
export const defaults: Policy = {
  ipLimit: 30,
  accountLimit: 10,
  rateWindowSeconds: 60,
  lockThreshold: 5,
  lockSeconds: 300,
  alertThreshold: 3,
  alertWindowSeconds: 900,
  sessionMinutes: 60,
  retentionLimit: 2000,
};
export type Config = {
  port: number;
  databasePath: string;
  trustedOrigins: string[];
  trustedProxyIps: string[];
  policy: Policy;
};
export function configuration(): Config {
  const port = z.coerce
    .number()
    .int()
    .min(1024)
    .max(65535)
    .parse(process.env.PORT || 3001);
  const trustedOrigins = (
    process.env.TRUSTED_ORIGINS ||
    process.env.LOCAL_ORIGIN ||
    "http://127.0.0.1:5173"
  )
    .split(",")
    .map((v) => v.trim());
  for (const origin of trustedOrigins) {
    const url = new URL(origin);
    if (
      url.origin !== origin ||
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      (url.protocol === "http:" &&
        !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))
    )
      throw new Error(
        "Trusted origins must be exact HTTPS origins or local loopback HTTP origins.",
      );
  }
  const trustedProxyIps = (process.env.TRUSTED_PROXY_IPS || "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
  if (trustedProxyIps.some((v) => !isIP(v)))
    throw new Error(
      "TRUSTED_PROXY_IPS must contain explicitly known IP addresses.",
    );
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  return {
    port,
    databasePath: process.env.DATABASE_PATH
      ? path.resolve(process.env.DATABASE_PATH)
      : path.join(root, "data", "portal.sqlite"),
    trustedOrigins,
    trustedProxyIps,
    policy: policySchema.parse({
      ...defaults,
      retentionLimit: Number(
        process.env.AUDIT_RETENTION_LIMIT || defaults.retentionLimit,
      ),
    }),
  };
}
export const usernameSchema = z
  .string()
  .trim()
  .min(3)
  .max(32)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/)
  .transform((v) => v.toLowerCase());
export const registrationSchema = z
  .object({ username: usernameSchema, password: z.string().min(15).max(128) })
  .strict();
export const loginSchema = z
  .object({
    username: usernameSchema,
    password: z.string().min(1).max(128),
    browserLocation: browserLocationSchema.optional(),
  })
  .strict();
export function safeUsername(input: unknown) {
  return typeof input === "string"
    ? input.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 64)
    : "";
}
