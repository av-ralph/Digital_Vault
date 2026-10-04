import { createApp } from "./app.js";
import { configuration } from "./config.js";
const config = configuration();
const service = createApp(config);
const server = service.app.listen(config.port, "127.0.0.1", () =>
  console.log(`Portal running locally at http://127.0.0.1:${config.port}`),
);
function stop() {
  server.close(() => {
    service.close();
    process.exit(0);
  });
  server.closeAllConnections();
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
