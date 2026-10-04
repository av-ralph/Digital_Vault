import type { Config, Context } from "@netlify/functions";
import { getConnectionString } from "@netlify/database";
import pg from "pg";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { CloudPortal } from "../../server/cloud.js";

let service: Promise<CloudPortal> | undefined;
async function portal(context: Context) {
  if (!service)
    service = (async () => {
      const connectionString =
        process.env.NETLIFY_DB_URL || getConnectionString();
      const pool = new pg.Pool({
        connectionString,
        max: 3,
        connectionTimeoutMillis: 10000,
        idleTimeoutMillis: 10000,
      });
      // Only platform-provided site URLs or explicit configuration are accepted.
      const origins = [
        ...new Set(
          [
            context.site.url,
            process.env.URL,
            process.env.DEPLOY_PRIME_URL,
            process.env.DEPLOY_URL,
            ...(process.env.TRUSTED_ORIGINS || "").split(","),
          ].filter((s): s is string => !!s),
        ),
      ];
      const html = await readFile(path.join(process.cwd(), "dist", "index.html"), "utf8")
        .catch(() => readFile(path.join(process.cwd(), "LoginLab", "dist", "index.html"), "utf8"));
      return new CloudPortal(pool, origins, html);
    })().catch((e) => {
      service = undefined;
      throw e;
    });
  return service;
}

export default async function handler(request: Request, context: Context) {
  try {
    // Netlify supplies context.ip. Never use browser-supplied forwarded headers.
    return await (await portal(context)).handle(request, context.ip || "unknown");
  } catch {
    return new Response(
      JSON.stringify({ message: "The service is temporarily unavailable." }),
      {
        status: 503,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        },
      },
    );
  }
}

// Protected HTML and API routes are handled on the server; assets stay on the CDN.
export const config: Config = {
  path: [
    "/",
    "/login",
    "/register",
    "/admin/login",
    "/account",
    "/admin",
    "/admin/settings",
    "/instructor",
    "/api/*",
  ],
};
