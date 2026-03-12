import { ChunkRequestStore } from "./chunk-store.js";
import { createHash } from "node:crypto";

const HOP_BY_HOP_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "proxy-connection",
  "transfer-encoding",
  "content-length"
]);
const REDACTED_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-relay-secret"
]);

function relayLog(config, event, payload = {}) {
  if (!config.relayDebugLog) {
    return;
  }
  const record = {
    ts: new Date().toISOString(),
    event,
    ...payload
  };
  console.log(`[relay-debug] ${JSON.stringify(record)}`);
}

function sanitizeHeaders(headers) {
  const sanitized = {};
  for (const [key, value] of Object.entries(headers || {})) {
    if (typeof value !== "string") {
      continue;
    }
    const lowered = key.toLowerCase();
    sanitized[lowered] = REDACTED_HEADERS.has(lowered) ? "<redacted>" : value;
  }
  return sanitized;
}

function isLikelyTextBody(contentType, sample) {
  const lowered = String(contentType || "").toLowerCase();
  if (
    lowered.startsWith("text/") ||
    lowered.includes("json") ||
    lowered.includes("xml") ||
    lowered.includes("javascript") ||
    lowered.includes("x-www-form-urlencoded")
  ) {
    return true;
  }
  if (!sample.length) {
    return true;
  }
  let controlBytes = 0;
  for (let index = 0; index < sample.length; index += 1) {
    const code = sample[index];
    if (code === 0) {
      return false;
    }
    if (code === 9 || code === 10 || code === 13) {
      continue;
    }
    if (code < 32 || code === 127) {
      controlBytes += 1;
    }
  }
  return controlBytes / sample.length < 0.05;
}

function bodyPreview(config, bodyBuffer, contentType) {
  if (!config.relayDebugLogBody) {
    return undefined;
  }
  const maxBytes = config.relayDebugBodyMaxBytes > 0 ? config.relayDebugBodyMaxBytes : 2048;
  const sample = bodyBuffer.subarray(0, maxBytes);
  const truncated = bodyBuffer.length > sample.length;
  if (isLikelyTextBody(contentType, sample)) {
    return {
      encoding: "utf8",
      totalBytes: bodyBuffer.length,
      truncated,
      preview: sample.toString("utf8")
    };
  }
  return {
    encoding: "base64",
    totalBytes: bodyBuffer.length,
    truncated,
    preview: sample.toString("base64")
  };
}

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
  const { createAbortSignal } = dependencies;

  async function handleInit(request, response) {
    if (!isRelayAuthorized(config, request)) {
      relayLog(config, "relay_auth_failed", {
        stage: "init",
        method: request.method,
        path: request.url || ""
      });
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const rawBody = await readRawBody(request);
    const contentType = typeof request.headers["content-type"] === "string" ? request.headers["content-type"] : "";
    const initBodyPreview = bodyPreview(config, rawBody, contentType);
    relayLog(config, "relay_init_body_received", {
      bytes: rawBody.length,
      contentType,
      bodyPreview: initBodyPreview
    });

    let body = {};
    try {
      body = rawBody.length ? JSON.parse(rawBody.toString("utf8")) : {};
    } catch (error) {
      relayLog(config, "relay_init_rejected", {
        reason: "invalid_json",
        parseError: error instanceof Error ? error.message : String(error),
        bodyPreview: initBodyPreview
      });
      sendJson(response, 400, { error: { message: "invalid relay init json payload" } });
      return true;
    }

    const initFieldTypes = {
      requestId: typeof body.requestId,
      chunkCount: typeof body.chunkCount,
      method: typeof body.method,
      path: typeof body.path
    };
    if (
      typeof body.requestId !== "string" ||
      typeof body.chunkCount !== "number" ||
      typeof body.method !== "string" ||
      typeof body.path !== "string"
    ) {
      relayLog(config, "relay_init_rejected", {
        reason: "invalid_payload_shape",
        fieldTypes: initFieldTypes,
        bodyPreview: initBodyPreview
      });
      sendJson(response, 400, {
        error: {
          message: "invalid relay init payload",
          details: initFieldTypes
        }
      });
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
      createdAt: Date.now()
    };

    relayLog(config, "relay_init_received", {
      requestId: metadata.requestId,
      method: metadata.method,
      path: metadata.path,
      targetUrl: metadata.targetUrl,
      chunkCount: metadata.chunkCount,
      bodySize: metadata.bodySize,
      bodySha256Set: Boolean(metadata.bodySha256),
      headers: sanitizeHeaders(metadata.headers),
      bodyPreview: initBodyPreview
    });
    await store.createRequest(metadata);
    sendJson(response, 202, { ok: true, requestId: body.requestId });
    return true;
  }

  async function handleChunk(request, response, requestId, index) {
    if (!isRelayAuthorized(config, request)) {
      relayLog(config, "relay_auth_failed", {
        stage: "chunk",
        requestId,
        index
      });
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const chunk = await readRawBody(request);
    const expectedSha256 = getHeader(request, "x-chunk-sha256");
    const expectedSize = getHeader(request, "x-chunk-size");
    const chunkPreview = bodyPreview(config, chunk, "application/octet-stream");

    if (expectedSize !== undefined && Number(expectedSize) !== chunk.length) {
      relayLog(config, "relay_chunk_rejected", {
        requestId,
        index,
        reason: "chunk_size_mismatch",
        expectedSize: Number(expectedSize),
        actualSize: chunk.length,
        chunkPreview
      });
      sendJson(response, 400, { error: { message: "chunk size mismatch" } });
      return true;
    }

    const actualChunkSha256 = expectedSha256 ? sha256Hex(chunk) : "";
    if (expectedSha256 && actualChunkSha256 !== expectedSha256) {
      relayLog(config, "relay_chunk_rejected", {
        requestId,
        index,
        reason: "chunk_checksum_mismatch",
        expectedSha256,
        actualSha256: actualChunkSha256,
        chunkPreview
      });
      sendJson(response, 400, { error: { message: "chunk checksum mismatch" } });
      return true;
    }

    relayLog(config, "relay_chunk_received", {
      requestId,
      index,
      chunkBytes: chunk.length,
      expectedSize: expectedSize !== undefined ? Number(expectedSize) : undefined,
      hasExpectedSha256: Boolean(expectedSha256),
      chunkPreview
    });
    await store.writeChunk(requestId, index, chunk);
    sendJson(response, 202, { ok: true, requestId, index, bytes: chunk.length });
    return true;
  }

  async function handleComplete(request, response) {
    if (!isRelayAuthorized(config, request)) {
      relayLog(config, "relay_auth_failed", {
        stage: "complete",
        method: request.method,
        path: request.url || ""
      });
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const abortSignal = createAbortSignal(request, response);
    const body = await readJsonBody(request);
    if (typeof body.requestId !== "string") {
      sendJson(response, 400, { error: { message: "invalid relay complete payload" } });
      return true;
    }

    let assembled;
    try {
      assembled = await store.assemble(body.requestId);
    } catch (error) {
      relayLog(config, "relay_complete_failed", {
        requestId: body.requestId,
        reason: error instanceof Error ? error.message : String(error)
      });
      sendJson(response, 409, {
        error: {
          message: error instanceof Error ? error.message : String(error)
        }
      });
      return true;
    }

    const { metadata, body: assembledBody } = assembled;
    const requestHeaders = normalizeStoredHeaders(metadata.headers);
    const assembledPreview = bodyPreview(config, assembledBody, requestHeaders["content-type"]);
    relayLog(config, "relay_complete_assembled", {
      requestId: body.requestId,
      method: metadata.method,
      path: metadata.path,
      targetUrl: metadata.targetUrl,
      chunkCount: metadata.chunkCount,
      bytes: assembledBody.length,
      bodyPreview: assembledPreview
    });
    if (metadata.bodySize && assembledBody.length !== metadata.bodySize) {
      relayLog(config, "relay_complete_failed", {
        requestId: body.requestId,
        reason: "assembled_body_size_mismatch",
        expectedSize: metadata.bodySize,
        actualSize: assembledBody.length
      });
      sendJson(response, 409, { error: { message: "assembled body size mismatch" } });
      return true;
    }
    if (metadata.bodySha256 && sha256Hex(assembledBody) !== metadata.bodySha256) {
      relayLog(config, "relay_complete_failed", {
        requestId: body.requestId,
        reason: "assembled_body_checksum_mismatch",
        expectedSha256: metadata.bodySha256,
        actualSha256: sha256Hex(assembledBody)
      });
      sendJson(response, 409, { error: { message: "assembled body checksum mismatch" } });
      return true;
    }

    console.log(
      `relay forwarding generic request method=${metadata.method} url=${metadata.targetUrl} bytes=${assembledBody.length}`
    );
    try {
      const upstream = await sendGenericUpstream(fetch, metadata, assembledBody, abortSignal);
      relayLog(config, "relay_upstream_response", {
        requestId: body.requestId,
        status: upstream.status,
        path: metadata.path
      });

      response.writeHead(upstream.status, proxyResponseHeaders(upstream));
      if (!upstream.body) {
        response.end();
        await store.remove(body.requestId);
        relayLog(config, "relay_complete_finished", { requestId: body.requestId });
        return true;
      }

      for await (const chunk of upstream.body) {
        response.write(chunk);
      }
      response.end();
      await store.remove(body.requestId);
      relayLog(config, "relay_complete_finished", { requestId: body.requestId });
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      relayLog(config, "relay_complete_failed", {
        requestId: body.requestId,
        reason: message,
        clientDisconnected: abortSignal.aborted
      });
      if (abortSignal.aborted) {
        if (!response.destroyed) {
          response.destroy();
        }
        return true;
      }
      if (!response.headersSent && !response.writableEnded) {
        sendJson(response, 502, { error: { message } });
        return true;
      }
      throw error;
    }
  }

  return {
    async maybeHandle(request, response, url) {
      if (request.method === "POST" && url.pathname === "/relay/v1/chunked/init") {
        relayLog(config, "relay_route_matched", { method: request.method, path: url.pathname });
        return handleInit(request, response);
      }

      const chunkMatch = /^\/relay\/v1\/chunked\/chunks\/([^/]+)\/(\d+)$/.exec(url.pathname);
      if (request.method === "PUT" && chunkMatch) {
        relayLog(config, "relay_route_matched", {
          method: request.method,
          path: url.pathname,
          requestId: chunkMatch[1],
          index: Number(chunkMatch[2])
        });
        return handleChunk(request, response, chunkMatch[1], Number(chunkMatch[2]));
      }

      if (request.method === "POST" && url.pathname === "/relay/v1/chunked/complete") {
        relayLog(config, "relay_route_matched", { method: request.method, path: url.pathname });
        return handleComplete(request, response);
      }
      return false;
    }
  };
}
