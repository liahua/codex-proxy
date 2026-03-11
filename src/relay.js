import { ChunkRequestStore } from "./chunk-store.js";
import { createHash } from "node:crypto";

const HOP_BY_HOP_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "proxy-connection",
  "transfer-encoding",
  "content-length"
]);

function sendJson(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload, null, 2));
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

function readRawBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function isRelayAuthorized(config, request) {
  if (!config.relaySharedSecret) {
    return true;
  }
  return request.headers["x-relay-secret"] === config.relaySharedSecret;
}

function normalizeStoredHeaders(headers) {
  const normalized = {};
  for (const [key, value] of Object.entries(headers || {})) {
    if (typeof value === "string") {
      normalized[key.toLowerCase()] = value;
    }
  }
  return normalized;
}

function buildForwardRequestHeaders(headers) {
  const forwarded = new Headers();
  for (const [key, value] of Object.entries(headers || {})) {
    const lowered = key.toLowerCase();
    if (typeof value !== "string" || HOP_BY_HOP_REQUEST_HEADERS.has(lowered)) {
      continue;
    }
    forwarded.set(lowered, value);
  }
  return forwarded;
}

function proxyResponseHeaders(upstream) {
  const headers = {};
  for (const [key, value] of upstream.headers.entries()) {
    if (key === "content-length") {
      continue;
    }
    headers[key] = value;
  }
  return headers;
}

function sha256Hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function getHeader(request, name) {
  const value = request.headers[name];
  return typeof value === "string" ? value : undefined;
}

function buildWsHttpRequestBody(event) {
  if (!event || typeof event !== "object") {
    throw new Error("invalid ws event payload");
  }

  if (event.type !== "response.create") {
    throw new Error(`unsupported ws event type: ${event.type || "unknown"}`);
  }

  if (event.response && typeof event.response === "object") {
    return { ...event.response };
  }

  const body = { ...event };
  delete body.type;
  delete body.id;
  return body;
}

async function sendGenericUpstream(fetchImpl, metadata, assembledBody, signal) {
  if (typeof metadata.targetUrl !== "string" || !metadata.targetUrl) {
    throw new Error("relay targetUrl is required for generic forwarding");
  }

  return fetchImpl(metadata.targetUrl, {
    method: typeof metadata.method === "string" ? metadata.method : "POST",
    headers: buildForwardRequestHeaders(metadata.headers),
    body: assembledBody,
    signal
  });
}

export function createRelayHandlers(config, dependencies) {
  const store = new ChunkRequestStore(config.relayStorageDir, config.relayRequestTtlMs);
  const { tokenManager, buildUpstreamRequest, sendToCodex, createAbortSignal } = dependencies;

  async function handleInit(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const body = await readJsonBody(request);
    if (
      typeof body.requestId !== "string" ||
      typeof body.chunkCount !== "number" ||
      !Array.isArray(body.headerAllowlist) ||
      typeof body.method !== "string" ||
      typeof body.path !== "string"
    ) {
      sendJson(response, 400, { error: { message: "invalid relay init payload" } });
      return true;
    }

    const metadata = {
      requestId: body.requestId,
      method: body.method,
      path: body.path,
      targetUrl: typeof body.targetUrl === "string" ? body.targetUrl : "",
      headers: normalizeStoredHeaders(body.headers),
      bodySize: typeof body.bodySize === "number" ? body.bodySize : 0,
      bodySha256: typeof body.bodySha256 === "string" ? body.bodySha256 : "",
      chunkCount: body.chunkCount,
      createdAt: Date.now(),
      headerAllowlist: body.headerAllowlist
    };

    await store.createRequest(metadata);
    sendJson(response, 202, { ok: true, requestId: body.requestId });
    return true;
  }

  async function handleChunk(request, response, requestId, index) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const chunk = await readRawBody(request);
    const expectedSha256 = getHeader(request, "x-chunk-sha256");
    const expectedSize = getHeader(request, "x-chunk-size");

    if (expectedSize !== undefined && Number(expectedSize) !== chunk.length) {
      sendJson(response, 400, { error: { message: "chunk size mismatch" } });
      return true;
    }

    if (expectedSha256 && sha256Hex(chunk) !== expectedSha256) {
      sendJson(response, 400, { error: { message: "chunk checksum mismatch" } });
      return true;
    }

    await store.writeChunk(requestId, index, chunk);
    sendJson(response, 202, { ok: true, requestId, index, bytes: chunk.length });
    return true;
  }

  async function handleComplete(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const body = await readJsonBody(request);
    if (typeof body.requestId !== "string") {
      sendJson(response, 400, { error: { message: "invalid relay complete payload" } });
      return true;
    }

    let assembled;
    try {
      assembled = await store.assemble(body.requestId);
    } catch (error) {
      sendJson(response, 409, {
        error: {
          message: error instanceof Error ? error.message : String(error)
        }
      });
      return true;
    }

    const { metadata, body: assembledBody } = assembled;
    if (metadata.bodySize && assembledBody.length !== metadata.bodySize) {
      sendJson(response, 409, { error: { message: "assembled body size mismatch" } });
      return true;
    }
    if (metadata.bodySha256 && sha256Hex(assembledBody) !== metadata.bodySha256) {
      sendJson(response, 409, { error: { message: "assembled body checksum mismatch" } });
      return true;
    }

    const requestHeaders = normalizeStoredHeaders(metadata.headers);
    let upstream;
    if (metadata.path === "/v1/responses") {
      const requestBody = JSON.parse(assembledBody.toString("utf8"));
      const credentials = await tokenManager.getCredentials(requestHeaders);
      const upstreamRequest = buildUpstreamRequest(config, requestBody, credentials, requestHeaders);
      upstream = await sendToCodex(fetch, upstreamRequest, createAbortSignal(request));
    } else {
      console.log(
        `relay forwarding generic request method=${metadata.method} url=${metadata.targetUrl} bytes=${assembledBody.length}`
      );
      upstream = await sendGenericUpstream(
        fetch,
        metadata,
        assembledBody,
        createAbortSignal(request)
      );
    }

    response.writeHead(upstream.status, proxyResponseHeaders(upstream));
    if (!upstream.body) {
      response.end();
      return true;
    }

    for await (const chunk of upstream.body) {
      response.write(chunk);
    }
    response.end();
    await store.remove(body.requestId);
      return true;
  }

  async function handleWsHttp(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const body = await readJsonBody(request);
    const requestHeaders = normalizeStoredHeaders(body.headers);

    let requestBody;
    try {
      requestBody = buildWsHttpRequestBody(body.event);
    } catch (error) {
      sendJson(response, 400, {
        error: { message: error instanceof Error ? error.message : String(error) }
      });
      return true;
    }
    if (requestBody.stream === undefined) {
      requestBody.stream = true;
    }

    const credentials = await tokenManager.getCredentials(requestHeaders);
    const upstreamRequest = buildUpstreamRequest(config, requestBody, credentials, requestHeaders);
    const upstream = await sendToCodex(fetch, upstreamRequest, createAbortSignal(request));

    response.writeHead(upstream.status, proxyResponseHeaders(upstream));
    if (!upstream.body) {
      response.end();
      return true;
    }

    for await (const chunk of upstream.body) {
      response.write(chunk);
    }
    response.end();
    return true;
  }

  return {
    async maybeHandle(request, response, url) {
      if (request.method === "POST" && url.pathname === "/relay/v1/chunked/init") {
        return handleInit(request, response);
      }

      const chunkMatch = /^\/relay\/v1\/chunked\/chunks\/([^/]+)\/(\d+)$/.exec(url.pathname);
      if (request.method === "PUT" && chunkMatch) {
        return handleChunk(request, response, chunkMatch[1], Number(chunkMatch[2]));
      }

      if (request.method === "POST" && url.pathname === "/relay/v1/chunked/complete") {
        return handleComplete(request, response);
      }

      if (request.method === "POST" && url.pathname === "/relay/v1/codex/ws-http") {
        return handleWsHttp(request, response);
      }

      return false;
    }
  };
}
