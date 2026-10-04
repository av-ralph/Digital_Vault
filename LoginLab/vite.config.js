import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: "protected-page-access",
      configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
          if (req.headers.host !== "127.0.0.1:5173") {
            res.statusCode = 403;
            res.end("Unexpected Host.");
            return;
          }
          const pathname = new URL(req.url || "/", "http://127.0.0.1:5173")
            .pathname;
          if (["/simulator", "/settings"].includes(pathname)) {
            res.statusCode = 404;
            res.end("Page not found.");
            return;
          }
          if (
            !["/account", "/admin", "/admin/settings", "/instructor"].includes(
              pathname,
            )
          )
            return next();
          try {
            const response = await fetch(
              "http://127.0.0.1:3001/api/access?role=" +
                (pathname === "/account" ? "user" : "admin"),
              { headers: { Cookie: req.headers.cookie || "" } },
            );
            if (response.status === 401) {
              res.statusCode = 302;
              res.setHeader(
                "Location",
                pathname === "/account" ? "/login" : "/admin/login",
              );
              res.end();
              return;
            }
            if (response.status !== 200) {
              res.statusCode = response.status;
              res.end("Administrator access required.");
              return;
            }
            next();
          } catch {
            res.statusCode = 503;
            res.end(
              "The local API is unavailable. Start both services with npm run dev.",
            );
          }
        });
      },
    },
  ],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: "http://127.0.0.1:3001" } },
  },
});
