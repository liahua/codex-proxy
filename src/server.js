import { createServer } from "node:http";
import { loadConfig } from "./config.js";
import { errorMessage, logError } from "./error-utils.js";
import { createRelayHandlers } from "./relay.js";
import { createUpstreamRouter } from "./upstream-router.js";

const config = loadConfig();
if (!config.relayUpstreamSslVerify) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const upstreamRouter = createUpstreamRouter(config);
const relayHandlers = createRelayHandlers(config, {
  createAbortSignal,
  upstreamRouter
});

function json(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload, null, 2));
}

function createAbortSignal(request, response) {
  const controller = new AbortController();
  const abort = () => {
    if (!controller.signal.aborted) {
      controller.abort();
    }
  };

  if (request.aborted || (response.destroyed && !response.writableEnded)) {
    abort();
  }

  request.on("aborted", abort);
  response.on("close", () => {
    if (!response.writableEnded) {
      abort();
    }
  });
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
        relayOnlyReady: true,
        upstreamMode: config.relayUpstreamMode
      });
      return;
    }

    // Only the relay protocol is served. A Codex client that reaches here is
    // talking to us directly, which means its interceptor is not running - and
    // that must fail loudly, not quietly send an unchunked request straight at
    // the gateway this relay exists to get past.
    json(response, 404, {
      error: {
        message:
          `Route not found: ${request.method} ${url.pathname}. ` +
          "This relay only accepts the v5 relay protocol; direct requests are refused. " +
          "Check that the local mitmproxy interceptor is running and intercepting this host."
      }
    });
  } catch (error) {
    const message = errorMessage(error);
    if (config.relayDebugLog) {
      logError("[server-error]", {
        method: request.method,
        url: request.url || ""
      }, error);
    }
    if (response.headersSent || response.writableEnded || response.destroyed) {
      if (!response.destroyed) {
        response.destroy(error instanceof Error ? error : undefined);
      }
      return;
    }
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
  console.log(`relay upstream ssl verify=${config.relayUpstreamSslVerify}`);
  console.log(
    `upstream mode=${config.relayUpstreamMode}` +
      (config.relayUpstreamMode === "cpa" ? ` cpa=${config.cpaBaseUrl}` : "")
  );
  if (config.relayDebugLog) {
    console.log(
      `relay debug enabled body=${config.relayDebugLogBody} maxBytes=${config.relayDebugBodyMaxBytes}`
    );
  }
});
