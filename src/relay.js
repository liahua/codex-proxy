import { ChunkRequestStore, RelayResponseSnapshotStore, RelaySnapshotStore } from "./chunk-store.js";
import { createUpstreamRouter } from "./upstream-router.js";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { gunzipSync, zstdDecompressSync } from "node:zlib";
import { errorMessage, logError, serializeError } from "./error-utils.js";

const AES_256_GCM = "aes-256-gcm";
const RESPONSE_ENCRYPTED_HEADER = "x-relay-response-encrypted";
const RESPONSE_FRAME_PROTOCOL = "aes-256-gcm-frame-v1";
const UPSTREAM_STATUS_HEADER = "x-relay-upstream-status";
const UPSTREAM_CONTENT_TYPE_HEADER = "x-relay-upstream-content-type";
const INTERNAL_CONTENT_ENCODING_GZIP = "gzip";
const SNAPSHOT_ID_HEADER = "x-relay-snapshot-id";
const SNAPSHOT_BODY_SHA256_HEADER = "x-relay-snapshot-body-sha256";
const SNAPSHOT_INPUT_COUNT_HEADER = "x-relay-snapshot-input-count";
const RESPONSE_SNAPSHOT_ID_HEADER = "x-relay-response-snapshot-id";

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

function proxyResponseHeaders(upstream) {
  const headers = {};
  for (const [key, value] of upstream.headers.entries()) {
    // fetch() already decoded the body, and we re-frame it ourselves, so the
    // upstream's length and encoding no longer describe what the client gets.
    // Forwarding content-encoding hands the client "compressed" plaintext.
    if (key === "content-length" || key === "content-encoding") {
      continue;
    }
    headers[key] = value;
  }
  return headers;
}

function sha256Hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function stableJsonStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJsonStringify(item)).join(",")}]`;
  }
  const entries = Object.entries(value)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries
    .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableJsonStringify(entryValue)}`)
    .join(",")}}`;
}

function canonicalJsonHash(value) {
  return sha256Hex(Buffer.from(stableJsonStringify(value), "utf8"));
}

function parseJsonRequestBody(bodyBuffer) {
  const parsed = JSON.parse(bodyBuffer.toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("relay body must be a JSON object");
  }
  return parsed;
}

function decodeRequestBodyForSnapshot(requestMetadata, bodyBuffer) {
  const headers = requestMetadata && requestMetadata.headers ? requestMetadata.headers : {};
  const contentEncoding = String(headers["content-encoding"] || "").trim().toLowerCase();
  if (!contentEncoding || contentEncoding === "identity") {
    return bodyBuffer;
  }
  if (contentEncoding === INTERNAL_CONTENT_ENCODING_GZIP) {
    return gunzipSync(bodyBuffer);
  }
  if (contentEncoding === "zstd") {
    return zstdDecompressSync(bodyBuffer);
  }
  throw new Error(`unsupported request content-encoding for snapshot: ${contentEncoding}`);
}

function inputItemHashes(body) {
  if (!Array.isArray(body.input)) {
    return [];
  }
  return body.input.map((item) => canonicalJsonHash(item));
}

function collectStringLeaves(value, minChars, output = []) {
  if (typeof value === "string") {
    if (value.length >= minChars) {
      output.push(value);
    }
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectStringLeaves(item, minChars, output);
    }
    return output;
  }
  if (value && typeof value === "object") {
    for (const entryValue of Object.values(value)) {
      collectStringLeaves(entryValue, minChars, output);
    }
  }
  return output;
}

function uniqueResponseTexts(texts) {
  const seen = new Set();
  const output = [];
  for (const text of texts) {
    const digest = sha256Hex(Buffer.from(text, "utf8"));
    if (seen.has(digest)) {
      continue;
    }
    seen.add(digest);
    output.push({
      sha256: digest,
      text
    });
  }
  return output;
}

function responseTextCandidates(bodyBuffer, contentType, minChars) {
  if (!isLikelyTextBody(contentType, bodyBuffer.subarray(0, Math.min(bodyBuffer.length, 2048)))) {
    return [];
  }
  const text = bodyBuffer.toString("utf8");
  const candidates = [];
  const lowered = String(contentType || "").toLowerCase();
  if (text.length >= minChars) {
    candidates.push(text);
  }
  if (lowered.includes("json")) {
    try {
      collectStringLeaves(JSON.parse(text), minChars, candidates);
    } catch {
      // Keep the raw text candidate only.
    }
  }
  if (lowered.includes("event-stream") || text.includes("\ndata:")) {
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("data:")) {
        continue;
      }
      const payload = trimmed.slice(5).trim();
      if (!payload || payload === "[DONE]") {
        continue;
      }
      try {
        collectStringLeaves(JSON.parse(payload), minChars, candidates);
      } catch {
        if (payload.length >= minChars) {
          candidates.push(payload);
        }
      }
    }
  }
  return uniqueResponseTexts(candidates);
}

function createSnapshotMetadata(requestMetadata, body) {
  const canonicalBodyJson = stableJsonStringify(body);
  return {
    snapshotId: `snap_${randomBytes(16).toString("hex")}`,
    createdAt: Date.now(),
    targetUrl: requestMetadata.targetUrl,
    path: requestMetadata.path,
    method: requestMetadata.method,
    bodySha256: canonicalJsonHash(body),
    bodySize: Buffer.byteLength(canonicalBodyJson),
    inputItemHashes: inputItemHashes(body)
  };
}

function snapshotResponseHeaders(snapshotMetadata) {
  return {
    [SNAPSHOT_ID_HEADER]: snapshotMetadata.snapshotId,
    [SNAPSHOT_BODY_SHA256_HEADER]: snapshotMetadata.bodySha256,
    [SNAPSHOT_INPUT_COUNT_HEADER]: String(snapshotMetadata.inputItemHashes.length)
  };
}

function responseSnapshotHeaders(snapshotId) {
  return {
    [RESPONSE_SNAPSHOT_ID_HEADER]: snapshotId
  };
}

function validateDeltaPayload(body) {
  if (
    typeof body.requestId !== "string" ||
    typeof body.baseSnapshotId !== "string" ||
    typeof body.baseBodySha256 !== "string" ||
    typeof body.method !== "string" ||
    typeof body.path !== "string" ||
    typeof body.targetUrl !== "string" ||
    !body.bodyFields ||
    typeof body.bodyFields !== "object" ||
    Array.isArray(body.bodyFields) ||
    !Array.isArray(body.appendInputItems)
  ) {
    throw new Error("invalid relay v4 delta payload");
  }
  if (Object.prototype.hasOwnProperty.call(body.bodyFields, "input")) {
    throw new Error("relay v4 bodyFields must not contain input");
  }
}

function validateRefPayload(body) {
  if (
    typeof body.requestId !== "string" ||
    typeof body.method !== "string" ||
    typeof body.path !== "string" ||
    typeof body.targetUrl !== "string" ||
    !body.bodyTemplate ||
    typeof body.bodyTemplate !== "object" ||
    Array.isArray(body.bodyTemplate)
  ) {
    throw new Error("invalid relay v4 ref payload");
  }
}

function isRelayRef(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    value.$relayRef &&
    typeof value.$relayRef === "object"
  );
}

async function expandRelayRefs(value, responseSnapshotStore) {
  if (isRelayRef(value)) {
    const ref = value.$relayRef;
    if (
      ref.type !== "responseText" ||
      typeof ref.snapshotId !== "string" ||
      typeof ref.sha256 !== "string"
    ) {
      throw new Error("invalid relay ref");
    }
    const text = await responseSnapshotStore.getText(ref.snapshotId, ref.sha256);
    if (sha256Hex(Buffer.from(text, "utf8")) !== ref.sha256) {
      throw new Error("response ref checksum mismatch");
    }
    return text;
  }
  if (Array.isArray(value)) {
    const output = [];
    for (const item of value) {
      output.push(await expandRelayRefs(item, responseSnapshotStore));
    }
    return output;
  }
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, entryValue] of Object.entries(value)) {
      output[key] = await expandRelayRefs(entryValue, responseSnapshotStore);
    }
    return output;
  }
  return value;
}

async function reconstructDeltaBody(snapshot, delta, responseSnapshotStore) {
  const snapshotBody = JSON.parse(snapshot.bodyJson);
  if (!snapshotBody || typeof snapshotBody !== "object" || Array.isArray(snapshotBody)) {
    throw new Error("invalid snapshot body");
  }
  if (snapshot.metadata.bodySha256 !== delta.baseBodySha256) {
    throw new Error("snapshot body checksum mismatch");
  }
  const baseInput = Array.isArray(snapshotBody.input) ? snapshotBody.input : [];
  const reconstructed = {
    ...snapshotBody,
    ...delta.bodyFields,
    input: [...baseInput, ...delta.appendInputItems]
  };
  const expanded = await expandRelayRefs(reconstructed, responseSnapshotStore);
  const canonicalBodySha256 = canonicalJsonHash(expanded);
  if (typeof delta.canonicalBodySha256 === "string" && delta.canonicalBodySha256 !== canonicalBodySha256) {
    throw new Error("reconstructed body checksum mismatch");
  }
  return {
    body: expanded,
    canonicalBodySha256
  };
}

function getHeader(request, name) {
  const value = request.headers[name];
  return typeof value === "string" ? value : undefined;
}

function decodeBase64(value, label) {
  if (typeof value !== "string" || !value) {
    throw new Error(`${label} is required`);
  }
  const buffer = Buffer.from(value, "base64");
  if (!buffer.length) {
    throw new Error(`${label} must be valid base64`);
  }
  return buffer;
}

function getEncryptionKey(config, keyId) {
  if (typeof keyId !== "string" || !keyId) {
    throw new Error("encryption keyId is required");
  }
  const raw = config.relayEncryptionKeys?.[keyId];
  if (typeof raw !== "string" || !raw) {
    throw new Error(`unknown encryption keyId: ${keyId}`);
  }
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error(`invalid encryption key length for keyId: ${keyId}`);
  }
  return key;
}

function encryptAesGcm(key, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(AES_256_GCM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

function decryptAesGcm(key, ivValue, tagValue, ciphertext) {
  const iv = Buffer.isBuffer(ivValue) ? ivValue : decodeBase64(ivValue, "iv");
  const tag = Buffer.isBuffer(tagValue) ? tagValue : decodeBase64(tagValue, "tag");
  const decipher = createDecipheriv(AES_256_GCM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function encodeFrame(header, payload = Buffer.alloc(0)) {
  const headerBuffer = Buffer.from(JSON.stringify({ ...header, payloadLength: payload.length }), "utf8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(headerBuffer.length, 0);
  return Buffer.concat([prefix, headerBuffer, payload]);
}

function decodeFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) {
      throw new Error("invalid encrypted frame prefix");
    }
    const headerLength = buffer.readUInt32BE(offset);
    offset += 4;
    if (offset + headerLength > buffer.length) {
      throw new Error("invalid encrypted frame header");
    }
    const header = JSON.parse(buffer.subarray(offset, offset + headerLength).toString("utf8"));
    offset += headerLength;
    const payloadLength =
      typeof header.payloadLength === "number" && header.payloadLength >= 0 ? header.payloadLength : 0;
    if (offset + payloadLength > buffer.length) {
      throw new Error("invalid encrypted frame payload");
    }
    frames.push({
      header,
      payload: buffer.subarray(offset, offset + payloadLength)
    });
    offset += payloadLength;
  }
  return frames;
}

function encodeEncryptedFrame(type, keyId, key, plaintext, extraHeader = {}) {
  const encrypted = encryptAesGcm(key, plaintext);
  return encodeFrame(
    {
      ...extraHeader,
      type,
      alg: AES_256_GCM,
      keyId,
      iv: encrypted.iv.toString("base64"),
      tag: encrypted.tag.toString("base64")
    },
    encrypted.ciphertext
  );
}

function decodeRequestChunkFrames(key, encryptedBody) {
  const plaintextChunks = [];
  for (const frame of decodeFrames(encryptedBody)) {
    if (frame.header.type !== "requestChunk") {
      throw new Error(`unexpected request frame type: ${frame.header.type}`);
    }
    plaintextChunks.push(decryptAesGcm(key, frame.header.iv, frame.header.tag, frame.payload));
  }
  return Buffer.concat(plaintextChunks);
}

async function sendGenericUpstream(fetchImpl, router, config, metadata, assembledBody, signal) {
  const resolved = router.resolve(metadata, assembledBody);
  relayLog(config, "relay_upstream_route", {
    requestId: metadata.requestId || "",
    path: metadata.path || "",
    targetUrl: metadata.targetUrl || "",
    upstreamUrl: resolved.url || "",
    routed: Boolean(resolved.routed),
    reason: resolved.reason,
    ...(resolved.mappedModel ? { model: resolved.model, mappedModel: resolved.mappedModel } : {}),
    ...(resolved.strippedTools?.length ? { strippedTools: resolved.strippedTools } : {})
  });

  if (resolved.drop) {
    return new Response(null, {
      status: 204,
      headers: { "x-relay-upstream": "dropped" }
    });
  }

  return fetchImpl(resolved.url, {
    method: resolved.method,
    headers: resolved.headers,
    body: resolved.body,
    signal
  });
}

function buildEncryptedOuterHeaders() {
  return {
    "content-type": "application/octet-stream",
    [RESPONSE_ENCRYPTED_HEADER]: RESPONSE_FRAME_PROTOCOL,
    "cache-control": "no-store"
  };
}

function parseV2Metadata(config, storedMetadata) {
  const key = getEncryptionKey(config, storedMetadata.enc.keyId);
  const plaintext = decryptAesGcm(
    key,
    storedMetadata.enc.iv,
    storedMetadata.enc.tag,
    Buffer.from(storedMetadata.enc.ciphertext, "base64")
  );
  const metadata = JSON.parse(plaintext.toString("utf8"));
  return {
    key,
    metadata: {
      requestId: storedMetadata.requestId,
      chunkCount: storedMetadata.chunkCount,
      createdAt: storedMetadata.createdAt,
      ...metadata
    }
  };
}

function isEncryptedChunkedPayloadInit(body) {
  const enc = body?.enc || {};
  return (
    typeof body?.requestId === "string" &&
    typeof body?.chunkCount === "number" &&
    typeof enc === "object" &&
    typeof enc.keyId === "string" &&
    enc.alg === AES_256_GCM &&
    typeof enc.iv === "string" &&
    typeof enc.tag === "string" &&
    typeof enc.ciphertext === "string"
  );
}

function validateEncryptedChunkedPayloadMetadata(config, storedMetadata, expectedVersion) {
  const parsed = parseV2Metadata(config, storedMetadata);
  const metadata = parsed.metadata;
  if (
    metadata.version !== expectedVersion ||
    typeof metadata.chunkCount !== "number" ||
    metadata.relayTransferEncoding !== INTERNAL_CONTENT_ENCODING_GZIP ||
    typeof metadata.bodySize !== "number" ||
    typeof metadata.bodySha256 !== "string" ||
    typeof metadata.compressedBodySize !== "number" ||
    typeof metadata.compressedBodySha256 !== "string"
  ) {
    throw new Error(`invalid ${expectedVersion} encrypted payload metadata`);
  }
  return parsed;
}

async function assembleEncryptedJsonPayload(config, store, requestId, expectedVersion) {
  const assembled = await store.assemble(requestId);
  const parsed = validateEncryptedChunkedPayloadMetadata(config, assembled.metadata, expectedVersion);
  const encryptedBody = decodeRequestChunkFrames(parsed.key, assembled.body);
  const decoded = decodeRelayCompressedBody(parsed.metadata, encryptedBody);
  const body = parseJsonRequestBody(decoded.body);
  return body;
}

function parseCompressionMetadata(metadata) {
  const relayTransferEncoding =
    typeof metadata.relayTransferEncoding === "string" && metadata.relayTransferEncoding
      ? metadata.relayTransferEncoding
      : typeof metadata.contentEncodingApplied === "string"
        ? metadata.contentEncodingApplied
        : "";
  return {
    bodySize: typeof metadata.bodySize === "number" ? metadata.bodySize : 0,
    bodySha256: typeof metadata.bodySha256 === "string" ? metadata.bodySha256 : "",
    compressedBodySize: typeof metadata.compressedBodySize === "number" ? metadata.compressedBodySize : 0,
    compressedBodySha256: typeof metadata.compressedBodySha256 === "string" ? metadata.compressedBodySha256 : "",
    relayTransferEncoding
  };
}

function decodeRelayCompressedBody(metadata, compressedBody) {
  const compression = parseCompressionMetadata(metadata);
  if (compression.relayTransferEncoding !== INTERNAL_CONTENT_ENCODING_GZIP) {
    throw new Error("unsupported relay content encoding");
  }
  if (compression.compressedBodySize && compressedBody.length !== compression.compressedBodySize) {
    throw new Error("assembled compressed body size mismatch");
  }
  if (
    compression.compressedBodySha256 &&
    sha256Hex(compressedBody) !== compression.compressedBodySha256
  ) {
    throw new Error("assembled compressed body checksum mismatch");
  }

  let decompressedBody;
  try {
    decompressedBody = gunzipSync(compressedBody);
  } catch {
    throw new Error("invalid gzip body");
  }

  if (compression.bodySize && decompressedBody.length !== compression.bodySize) {
    throw new Error("assembled body size mismatch");
  }
  if (compression.bodySha256 && sha256Hex(decompressedBody) !== compression.bodySha256) {
    throw new Error("assembled body checksum mismatch");
  }
  return {
    body: decompressedBody,
    compression
  };
}

export function createRelayHandlers(config, dependencies) {
  const upstreamRouter = dependencies.upstreamRouter || createUpstreamRouter(config);
  const store = new ChunkRequestStore(config.relayStorageDir, config.relayRequestTtlMs);
  const snapshotStore = new RelaySnapshotStore(config.relayStorageDir, config.relaySnapshotTtlMs);
  const responseSnapshotStore = new RelayResponseSnapshotStore(
    config.relayStorageDir,
    config.relayResponseSnapshotTtlMs
  );
  const { createAbortSignal } = dependencies;

  /**
   * Every v4 response is encrypted, under the same key the client used to
   * encrypt the request. There is no plaintext path to fall back to.
   */
  function responseEncryptionFor(keyId) {
    return { keyId, key: getEncryptionKey(config, keyId) };
  }

  /**
   * Writes the upstream response back to the relay client, either verbatim or
   * as AES-256-GCM frames when the client asked for an encrypted response.
   * Returns the plaintext body buffers so callers can still snapshot them.
   */
  async function streamUpstreamResponse(response, upstream, extraHeaders, encryption) {
    const responseBuffers = [];
    const headers = { ...proxyResponseHeaders(upstream), ...extraHeaders };

    if (!encryption) {
      response.writeHead(upstream.status, headers);
      if (upstream.body) {
        for await (const chunk of upstream.body) {
          const buffer = Buffer.from(chunk);
          responseBuffers.push(buffer);
          response.write(buffer);
        }
      }
      return responseBuffers;
    }

    // The client has to know the real status, content type and snapshot ids
    // *before* the body starts, otherwise it cannot stream: it would have to
    // buffer the whole response just to read the encrypted meta frame, which
    // stalls SSE until the model has finished generating. These are ids and
    // content types, never response content; the payload stays encrypted.
    response.writeHead(200, {
      ...buildEncryptedOuterHeaders(),
      ...extraHeaders,
      [UPSTREAM_STATUS_HEADER]: String(upstream.status),
      ...(headers["content-type"] ? { [UPSTREAM_CONTENT_TYPE_HEADER]: headers["content-type"] } : {})
    });
    response.write(
      encodeEncryptedFrame(
        "meta",
        encryption.keyId,
        encryption.key,
        Buffer.from(JSON.stringify({ status: upstream.status, headers }), "utf8"),
        { seq: 0 }
      )
    );

    let seq = 1;
    if (upstream.body) {
      for await (const chunk of upstream.body) {
        const buffer = Buffer.from(chunk);
        responseBuffers.push(buffer);
        response.write(encodeEncryptedFrame("data", encryption.keyId, encryption.key, buffer, { seq }));
        seq += 1;
      }
    }
    return responseBuffers;
  }

  /** Shared error tail for every complete handler. */
  function handleUpstreamFailure(response, error, { requestId, path, version, abortSignal }) {
    const message = errorMessage(error);
    relayLog(config, "relay_complete_failed", {
      requestId,
      version,
      reason: message,
      error: serializeError(error),
      clientDisconnected: abortSignal.aborted
    });
    if (config.relayDebugLog) {
      logError("[relay-upstream-error]", { requestId, path, version, clientDisconnected: abortSignal.aborted }, error);
    }
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

  /**
   * v4 "full" upload: the whole request body, gzipped, AES-256-GCM chunked.
   * Used for the first turn of a conversation, and whenever no reusable
   * snapshot exists for a delta.
   */
  async function handleFullInit(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    let body;
    try {
      body = await readJsonBody(request);
    } catch {
      sendJson(response, 400, { error: { message: "invalid relay init json payload" } });
      return true;
    }

    if (!isEncryptedChunkedPayloadInit(body)) {
      sendJson(response, 400, {
        error: { message: "invalid relay v4 full init payload: an encrypted envelope is required" }
      });
      return true;
    }

    const enc = body.enc;
    try {
      const key = getEncryptionKey(config, enc.keyId);
      const plaintext = decryptAesGcm(key, enc.iv, enc.tag, Buffer.from(enc.ciphertext, "base64"));
      const metadata = JSON.parse(plaintext.toString("utf8"));
      if (
        typeof metadata.method !== "string" ||
        typeof metadata.path !== "string" ||
        typeof metadata.targetUrl !== "string" ||
        typeof metadata.chunkCount !== "number" ||
        metadata.relayTransferEncoding !== INTERNAL_CONTENT_ENCODING_GZIP ||
        typeof metadata.compressedBodySize !== "number"
      ) {
        sendJson(response, 400, { error: { message: "invalid relay v4 full metadata payload" } });
        return true;
      }
    } catch (error) {
      sendJson(response, 400, {
        error: { message: error instanceof Error ? error.message : String(error) }
      });
      return true;
    }

    await store.createRequest({
      version: "v4-full",
      requestId: body.requestId,
      chunkCount: body.chunkCount,
      createdAt: Date.now(),
      enc
    });
    relayLog(config, "relay_v4_full_init_received", {
      requestId: body.requestId,
      chunkCount: body.chunkCount,
      keyId: enc.keyId
    });
    sendJson(response, 202, { ok: true, requestId: body.requestId, version: "v4" });
    return true;
  }

  async function handleCompleteFull(request, response) {
    if (!isRelayAuthorized(config, request)) {
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
      if (assembled.metadata.version !== "v4-full") {
        throw new Error("request is not a v4 full upload");
      }
    } catch (error) {
      sendJson(response, 409, {
        error: { message: error instanceof Error ? error.message : String(error) }
      });
      return true;
    }

    let parsed;
    let requestMetadata;
    let responseEncryption;
    let decompressedBody;
    try {
      parsed = parseV2Metadata(config, assembled.metadata);
      responseEncryption = responseEncryptionFor(assembled.metadata.enc.keyId);
      requestMetadata = {
        requestId: body.requestId,
        method: parsed.metadata.method,
        path: parsed.metadata.path,
        targetUrl: parsed.metadata.targetUrl,
        headers: normalizeStoredHeaders(parsed.metadata.headers)
      };
      decompressedBody = decodeRelayCompressedBody(
        parsed.metadata,
        decodeRequestChunkFrames(parsed.key, assembled.body)
      ).body;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      sendJson(response, message === "invalid gzip body" ? 400 : 409, { error: { message } });
      return true;
    }

    relayLog(config, "relay_v4_full_assembled", {
      requestId: body.requestId,
      method: requestMetadata.method,
      path: requestMetadata.path,
      chunkCount: assembled.metadata.chunkCount,
      bytes: decompressedBody.length,
      keyId: assembled.metadata.enc.keyId
    });

    try {
      const upstream = await sendGenericUpstream(
        fetch,
        upstreamRouter,
        config,
        requestMetadata,
        decompressedBody,
        abortSignal
      );
      const snapshotMetadata = await persistSnapshotForBody(requestMetadata, decompressedBody, body.requestId);
      const responseSnapshotId = `resp_${randomBytes(16).toString("hex")}`;
      relayLog(config, "relay_v4_full_upstream_response", {
        requestId: body.requestId,
        status: upstream.status,
        path: requestMetadata.path
      });

      const responseBuffers = await streamUpstreamResponse(
        response,
        upstream,
        {
          ...(snapshotMetadata ? snapshotResponseHeaders(snapshotMetadata) : {}),
          ...responseSnapshotHeaders(responseSnapshotId)
        },
        responseEncryption
      );
      await persistResponseSnapshot(responseSnapshotId, upstream, responseBuffers, body.requestId);
      response.end();
      await store.remove(body.requestId);
      relayLog(config, "relay_v4_full_finished", { requestId: body.requestId, status: upstream.status });
      return true;
    } catch (error) {
      return handleUpstreamFailure(response, error, {
        requestId: body.requestId,
        path: requestMetadata.path,
        version: "v4-full",
        abortSignal
      });
    }
  }

  async function handleEncryptedChunk(request, response, requestId, index) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const chunk = await readRawBody(request);
    const expectedSha256 = getHeader(request, "x-chunk-sha256");
    const expectedSize = getHeader(request, "x-chunk-size");
    const iv = getHeader(request, "x-chunk-iv");
    const tag = getHeader(request, "x-chunk-tag");

    if (!iv || !tag) {
      sendJson(response, 400, { error: { message: "missing chunk encryption headers" } });
      return true;
    }
    if (expectedSize !== undefined && Number(expectedSize) !== chunk.length) {
      sendJson(response, 400, { error: { message: "chunk size mismatch" } });
      return true;
    }
    if (expectedSha256 && sha256Hex(chunk) !== expectedSha256) {
      sendJson(response, 400, { error: { message: "chunk checksum mismatch" } });
      return true;
    }

    const packedChunk = encodeFrame(
      {
        type: "requestChunk",
        alg: AES_256_GCM,
        iv,
        tag
      },
      chunk
    );
    await store.writeChunk(requestId, index, packedChunk);
    relayLog(config, "relay_v4_chunk_received", {
      requestId,
      index,
      ciphertextBytes: chunk.length
    });
    sendJson(response, 202, { ok: true, requestId, index, bytes: chunk.length, version: "v4" });
    return true;
  }

  async function persistSnapshotForBody(requestMetadata, bodyBuffer, sourceRequestId) {
    try {
      const snapshotBodyBuffer = decodeRequestBodyForSnapshot(requestMetadata, bodyBuffer);
      const body = parseJsonRequestBody(snapshotBodyBuffer);
      const snapshotMetadata = createSnapshotMetadata(requestMetadata, body);
      await snapshotStore.createSnapshot(snapshotMetadata, stableJsonStringify(body));
      relayLog(config, "relay_snapshot_created", {
        requestId: sourceRequestId,
        snapshotId: snapshotMetadata.snapshotId,
        bodySha256: snapshotMetadata.bodySha256,
        inputItemCount: snapshotMetadata.inputItemHashes.length,
        targetUrl: snapshotMetadata.targetUrl
      });
      return snapshotMetadata;
    } catch (error) {
      relayLog(config, "relay_snapshot_skipped", {
        requestId: sourceRequestId,
        reason: error instanceof Error ? error.message : String(error)
      });
      return null;
    }
  }

  async function persistResponseSnapshot(snapshotId, upstream, buffers, sourceRequestId) {
    const bodyBuffer = Buffer.concat(buffers);
    if (!bodyBuffer.length) {
      return null;
    }
    const contentType = upstream.headers.get("content-type") || "";
    const texts = responseTextCandidates(bodyBuffer, contentType, config.relayResponseRefMinChars);
    if (!texts.length) {
      relayLog(config, "relay_response_snapshot_skipped", {
        requestId: sourceRequestId,
        snapshotId,
        reason: "no_text_candidates",
        contentType
      });
      return null;
    }
    const metadata = {
      snapshotId,
      createdAt: Date.now(),
      status: upstream.status,
      contentType,
      bodyBytes: bodyBuffer.length,
      bodySha256: sha256Hex(bodyBuffer),
      textCount: texts.length,
      minChars: config.relayResponseRefMinChars
    };
    await responseSnapshotStore.createSnapshot(metadata, texts);
    relayLog(config, "relay_response_snapshot_created", {
      requestId: sourceRequestId,
      snapshotId,
      status: upstream.status,
      contentType,
      bodyBytes: bodyBuffer.length,
      textCount: texts.length
    });
    return metadata;
  }

  async function handleDeltaV4(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    let body;
    try {
      body = await readJsonBody(request);
      if (!isEncryptedChunkedPayloadInit(body)) {
        sendJson(response, 400, {
          error: { message: "invalid relay v4 delta init payload: an encrypted envelope is required" }
        });
        return true;
      }
      const storedMetadata = {
        version: "v4-delta-chunked",
        requestId: body.requestId,
        chunkCount: body.chunkCount,
        createdAt: Date.now(),
        enc: body.enc
      };
      validateEncryptedChunkedPayloadMetadata(config, storedMetadata, "v4-delta-chunked");
      await store.createRequest(storedMetadata);
      relayLog(config, "relay_v4_delta_init_received", {
        requestId: body.requestId,
        chunkCount: body.chunkCount,
        keyId: body.enc.keyId
      });
      sendJson(response, 202, { ok: true, requestId: body.requestId, version: "v4", chunked: true });
      return true;
    } catch (error) {
      sendJson(response, 400, { error: { message: error instanceof Error ? error.message : String(error) } });
      return true;
    }
  }

  async function handleRefsV4(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    let body;
    try {
      body = await readJsonBody(request);
      if (!isEncryptedChunkedPayloadInit(body)) {
        sendJson(response, 400, {
          error: { message: "invalid relay v4 refs init payload: an encrypted envelope is required" }
        });
        return true;
      }
      const storedMetadata = {
        version: "v4-refs-chunked",
        requestId: body.requestId,
        chunkCount: body.chunkCount,
        createdAt: Date.now(),
        enc: body.enc
      };
      validateEncryptedChunkedPayloadMetadata(config, storedMetadata, "v4-refs-chunked");
      await store.createRequest(storedMetadata);
      relayLog(config, "relay_v4_refs_init_received", {
        requestId: body.requestId,
        chunkCount: body.chunkCount,
        keyId: body.enc.keyId
      });
      sendJson(response, 202, { ok: true, requestId: body.requestId, version: "v4", chunked: true });
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      sendJson(response, message.includes("response ref") ? 409 : 400, { error: { message } });
      return true;
    }
  }

  async function handleCompleteDeltaV4(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const abortSignal = createAbortSignal(request, response);
    const body = await readJsonBody(request);
    if (typeof body.requestId !== "string") {
      sendJson(response, 400, { error: { message: "invalid relay complete payload" } });
      return true;
    }

    let responseEncryption;
    let deltaMetadata;
    let snapshot;
    try {
      const storedMetadata = await store.getRequest(body.requestId);
      if (storedMetadata.version !== "v4-delta-chunked") {
        throw new Error("request is not a v4 delta");
      }
      responseEncryption = responseEncryptionFor(storedMetadata.enc.keyId);
      deltaMetadata = await assembleEncryptedJsonPayload(config, store, body.requestId, "v4-delta-chunked");
      validateDeltaPayload(deltaMetadata);
      snapshot = await snapshotStore.getSnapshot(deltaMetadata.baseSnapshotId);
    } catch (error) {
      sendJson(response, 409, { error: { message: error instanceof Error ? error.message : String(error) } });
      return true;
    }

    let reconstructed;
    try {
      reconstructed = await reconstructDeltaBody(snapshot, deltaMetadata, responseSnapshotStore);
    } catch (error) {
      sendJson(response, 409, { error: { message: error instanceof Error ? error.message : String(error) } });
      return true;
    }

    const requestMetadata = {
      requestId: deltaMetadata.requestId,
      method: deltaMetadata.method,
      path: deltaMetadata.path,
      targetUrl: deltaMetadata.targetUrl,
      headers: normalizeStoredHeaders(deltaMetadata.headers)
    };
    const reconstructedBodyBuffer = Buffer.from(stableJsonStringify(reconstructed.body), "utf8");

    try {
      const upstream = await sendGenericUpstream(fetch, upstreamRouter, config, requestMetadata, reconstructedBodyBuffer, abortSignal);
      const snapshotMetadata = await persistSnapshotForBody(requestMetadata, reconstructedBodyBuffer, body.requestId);
      relayLog(config, "relay_v4_delta_upstream_response", {
        requestId: body.requestId,
        status: upstream.status,
        path: requestMetadata.path,
        canonicalBodySha256: reconstructed.canonicalBodySha256
      });
      const responseSnapshotId = `resp_${randomBytes(16).toString("hex")}`;

      const responseBuffers = await streamUpstreamResponse(
        response,
        upstream,
        {
          ...(snapshotMetadata ? snapshotResponseHeaders(snapshotMetadata) : {}),
          ...responseSnapshotHeaders(responseSnapshotId)
        },
        responseEncryption
      );
      await persistResponseSnapshot(responseSnapshotId, upstream, responseBuffers, body.requestId);
      response.end();
      await store.remove(body.requestId);
      return true;
    } catch (error) {
      const message = errorMessage(error);
      relayLog(config, "relay_v4_delta_complete_failed", {
        requestId: body.requestId,
        reason: message,
        error: serializeError(error),
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

  async function handleCompleteV4(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    const abortSignal = createAbortSignal(request, response);
    const body = await readJsonBody(request);
    if (typeof body.requestId !== "string") {
      sendJson(response, 400, { error: { message: "invalid relay complete payload" } });
      return true;
    }

    let responseEncryption;
    let refMetadata;
    let expandedBody;
    try {
      const storedMetadata = await store.getRequest(body.requestId);
      if (storedMetadata.version !== "v4-refs-chunked") {
        throw new Error("request is not a v4 refs request");
      }
      responseEncryption = responseEncryptionFor(storedMetadata.enc.keyId);
      refMetadata = await assembleEncryptedJsonPayload(config, store, body.requestId, "v4-refs-chunked");
      validateRefPayload(refMetadata);
      expandedBody = await expandRelayRefs(refMetadata.bodyTemplate, responseSnapshotStore);
      const canonicalBodySha256 = canonicalJsonHash(expandedBody);
      if (refMetadata.canonicalBodySha256 && refMetadata.canonicalBodySha256 !== canonicalBodySha256) {
        throw new Error("expanded body checksum mismatch");
      }
    } catch (error) {
      sendJson(response, 409, { error: { message: error instanceof Error ? error.message : String(error) } });
      return true;
    }

    const requestMetadata = {
      requestId: refMetadata.requestId,
      method: refMetadata.method,
      path: refMetadata.path,
      targetUrl: refMetadata.targetUrl,
      headers: normalizeStoredHeaders(refMetadata.headers)
    };
    const expandedBodyBuffer = Buffer.from(stableJsonStringify(expandedBody), "utf8");

    try {
      const upstream = await sendGenericUpstream(fetch, upstreamRouter, config, requestMetadata, expandedBodyBuffer, abortSignal);
      const snapshotMetadata = await persistSnapshotForBody(requestMetadata, expandedBodyBuffer, body.requestId);
      const responseSnapshotId = `resp_${randomBytes(16).toString("hex")}`;
      relayLog(config, "relay_v4_upstream_response", {
        requestId: body.requestId,
        status: upstream.status,
        path: requestMetadata.path
      });

      const responseBuffers = await streamUpstreamResponse(
        response,
        upstream,
        {
          ...(snapshotMetadata ? snapshotResponseHeaders(snapshotMetadata) : {}),
          ...responseSnapshotHeaders(responseSnapshotId)
        },
        responseEncryption
      );
      await persistResponseSnapshot(responseSnapshotId, upstream, responseBuffers, body.requestId);
      response.end();
      await store.remove(body.requestId);
      return true;
    } catch (error) {
      const message = errorMessage(error);
      relayLog(config, "relay_v4_complete_failed", {
        requestId: body.requestId,
        reason: message,
        error: serializeError(error),
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
      // v4 is the only wire protocol: every request body is AES-256-GCM
      // chunked, and every response comes back as encrypted frames.
      //   full  - the whole body (first turn, or no reusable snapshot)
      //   delta - only the new input tail, rebuilt against a stored snapshot
      //   refs  - body with prior response text replaced by $relayRef markers
      const initMatch = /^\/relay\/v4\/(full|delta|refs)\/init$/.exec(url.pathname);
      if (request.method === "POST" && initMatch) {
        const kind = initMatch[1];
        relayLog(config, "relay_route_matched", { method: request.method, path: url.pathname, kind });
        if (kind === "full") {
          return handleFullInit(request, response);
        }
        return kind === "delta" ? handleDeltaV4(request, response) : handleRefsV4(request, response);
      }

      const chunkMatch = /^\/relay\/v4\/(?:full|delta|refs)\/chunks\/([^/]+)\/(\d+)$/.exec(url.pathname);
      if (request.method === "PUT" && chunkMatch) {
        relayLog(config, "relay_route_matched", {
          method: request.method,
          path: url.pathname,
          requestId: chunkMatch[1],
          index: Number(chunkMatch[2])
        });
        return handleEncryptedChunk(request, response, chunkMatch[1], Number(chunkMatch[2]));
      }

      const completeMatch = /^\/relay\/v4\/(full|delta|refs)\/complete$/.exec(url.pathname);
      if (request.method === "POST" && completeMatch) {
        const kind = completeMatch[1];
        relayLog(config, "relay_route_matched", { method: request.method, path: url.pathname, kind });
        if (kind === "full") {
          return handleCompleteFull(request, response);
        }
        return kind === "delta"
          ? handleCompleteDeltaV4(request, response)
          : handleCompleteV4(request, response);
      }

      return false;
    }
  };
}
