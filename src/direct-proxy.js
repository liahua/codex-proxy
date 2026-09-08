import { errorMessage, logError, serializeError } from "./error-utils.js";
import { createUpstreamRouter } from "./upstream-router.js";

// Paths a Codex client can hit directly, without the chunk relay protocol.
// This is the "simple config" path: point the CLI at the relay and
// authenticate with the shared secret as a bearer token.
const DIRECT_POST_PATHS = new Set([
  "/v1/responses",
  "/v1/responses/compact",
  "/backend-api/codex/responses",
  "/backend-api/codex/responses/compact"
]);

const DIRECT_GET_PATHS = new Set(["/v1/models", "/backend-api/codex/models"]);

function sendJson(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload, null, 2));
}

function readRawBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function bearerToken(headerValue) {
  if (typeof headerValue !== "string") {
    return "";
  }
  const match = /^Bearer\s+(.+)$/i.exec(headerValue.trim());
  return match ? match[1].trim() : "";
}

/**
 * Accepts the shared secret either as a bearer token (what the Codex CLI
 * sends for an api-key provider) or as the x-relay-secret header.
 */
function isDirectAuthorized(config, request) {
  if (!config.relaySharedSecret) {
    return true;
  }
  if (request.headers["x-relay-secret"] === config.relaySharedSecret) {
    return true;
  }
  return bearerToken(request.headers.authorization) === config.relaySharedSecret;
}

function requestHeaders(request) {
  const headers = {};
  for (const [key, value] of Object.entries(request.headers)) {
    if (typeof value === "string") {
      headers[key.toLowerCase()] = value;
    }
  }
  return headers;
}

function relayRouteLog(config, path, resolved) {
  console.log(
    JSON.stringify({
      event: "direct_upstream_route",
      path,
      upstreamUrl: resolved.url || "",
      routed: Boolean(resolved.routed),
      reason: resolved.reason,
      ...(resolved.mappedModel ? { model: resolved.model, mappedModel: resolved.mappedModel } : {}),
      ...(resolved.strippedTools?.length ? { strippedTools: resolved.strippedTools } : {})
    })
  );
}

function upstreamResponseHeaders(upstream) {
  const headers = {};
  for (const [key, value] of upstream.headers.entries()) {
    if (key === "content-length" || key === "content-encoding") {
      continue;
    }
    headers[key] = value;
  }
  return headers;
}

export function createDirectProxyHandlers(config, dependencies = {}) {
  const upstreamRouter = dependencies.upstreamRouter || createUpstreamRouter(config);
  const { createAbortSignal } = dependencies;

  async function forward(request, response, url, method, bodyBuffer) {
    const abortSignal = createAbortSignal(request, response);
    const metadata = {
      method,
      path: url.pathname,
      // In cpa mode the router only needs the path; targetUrl keeps
      // passthrough mode working for a directly-proxied Codex client too.
      targetUrl: `https://chatgpt.com${url.pathname}${url.search || ""}`,
      headers: requestHeaders(request)
    };

    let resolved;
    try {
      resolved = upstreamRouter.resolve(metadata, bodyBuffer);
    } catch (error) {
      sendJson(response, 500, { error: { message: errorMessage(error) } });
      return true;
    }

    if (config.relayDebugLog) {
      relayRouteLog(config, url.pathname, resolved);
    }

    if (resolved.drop) {
      response.writeHead(204).end();
      return true;
    }

    try {
      const upstream = await fetch(resolved.url, {
        method: resolved.method,
        headers: resolved.headers,
        body: method === "GET" || method === "HEAD" ? undefined : resolved.body,
        signal: abortSignal
      });

      response.writeHead(upstream.status, upstreamResponseHeaders(upstream));
      if (upstream.body) {
        for await (const chunk of upstream.body) {
          response.write(Buffer.from(chunk));
        }
      }
      response.end();
      return true;
    } catch (error) {
      if (config.relayDebugLog) {
        logError("[direct-upstream-error]", {
          path: url.pathname,
          upstreamUrl: resolved.url,
          clientDisconnected: abortSignal.aborted,
          error: serializeError(error)
        }, error);
      }
      if (abortSignal.aborted) {
        if (!response.destroyed) {
          response.destroy();
        }
        return true;
      }
      if (!response.headersSent && !response.writableEnded) {
        sendJson(response, 502, { error: { message: errorMessage(error) } });
        return true;
      }
      throw error;
    }
  }

  return {
    async maybeHandle(request, response, url) {
      const isPost = request.method === "POST" && DIRECT_POST_PATHS.has(url.pathname);
      const isGet = request.method === "GET" && DIRECT_GET_PATHS.has(url.pathname);
      if (!isPost && !isGet) {
        return false;
      }

      if (!isDirectAuthorized(config, request)) {
        sendJson(response, 401, {
          error: { message: "direct proxy auth failed: send the relay secret as a bearer token" }
        });
        return true;
      }

      const bodyBuffer = isPost ? await readRawBody(request) : Buffer.alloc(0);
      return forward(request, response, url, request.method, bodyBuffer);
    }
  };
}
