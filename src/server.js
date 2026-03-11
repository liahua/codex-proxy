import { createServer } from "node:http";
import { loadConfig } from "./config.js";
import { createRelayHandlers } from "./relay.js";

const config = loadConfig();
const relayHandlers = createRelayHandlers(config, {
  createAbortSignal
});

function json(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload, null, 2));
}

function createAbortSignal(request) {
  const controller = new AbortController();
  request.on("close", () => controller.abort());
  request.on("aborted", () => controller.abort());
  return controller.signal;
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }

    if (request.method === "GET" && url.pathname === "/healthz") {
      json(response, 200, {
        ok: true,
        relayStorageDir: config.relayStorageDir,
        relayOnlyReady: true
      });
      return;
    }

    json(response, 404, {
      error: {
        message: `Route not found: ${request.method} ${url.pathname}`
      }
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    json(response, 500, {
      error: {
        message
      }
    });
  }
});

server.on("upgrade", (_request, socket) => {
  const payload = "WebSocket relay disabled; please use HTTP fallback.";
  socket.write(
    `HTTP/1.1 503 Service Unavailable\r\n` +
      `content-type: text/plain; charset=utf-8\r\n` +
      `content-length: ${Buffer.byteLength(payload)}\r\n` +
      `connection: close\r\n\r\n` +
      payload
  );
  socket.destroy();
});

server.listen(config.port, config.host, () => {
  console.log(`codex-proxy listening on http://${config.host}:${config.port}`);
  if (config.relayDebugLog) {
    console.log(
      `relay debug enabled body=${config.relayDebugLogBody} maxBytes=${config.relayDebugBodyMaxBytes}`
    );
  }
});
