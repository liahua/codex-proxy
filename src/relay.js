import { ChunkRequestStore, RelaySnapshotStore } from "./chunk-store.js";
import { createUpstreamRouter } from "./upstream-router.js";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { zstdDecompressSync } from "node:zlib";
import { errorMessage, logError, serializeError } from "./error-utils.js";

const AES_256_GCM = "aes-256-gcm";
const RESPONSE_ENCRYPTED_HEADER = "x-relay-response-encrypted";
const RESPONSE_FRAME_PROTOCOL = "aes-256-gcm-frame-v1";
const UPSTREAM_STATUS_HEADER = "x-relay-upstream-status";
const UPSTREAM_CONTENT_TYPE_HEADER = "x-relay-upstream-content-type";
const TRANSFER_ENCODING_ZSTD = "zstd";
const SNAPSHOT_ID_HEADER = "x-relay-snapshot-id";
const SNAPSHOT_BODY_SHA256_HEADER = "x-relay-snapshot-body-sha256";

function relayLog(config, event, payload = {}) {
  if (!config.relayDebugLog) {
    return;
  }
  console.log(`[relay-debug] ${JSON.stringify({ ts: new Date().toISOString(), event, ...payload })}`);
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
  return { iv, ciphertext, tag: cipher.getAuthTag() };
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
    frames.push({ header, payload: buffer.subarray(offset, offset + payloadLength) });
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

function buildEncryptedOuterHeaders() {
  return {
    "content-type": "application/octet-stream",
    [RESPONSE_ENCRYPTED_HEADER]: RESPONSE_FRAME_PROTOCOL,
    "cache-control": "no-store"
  };
}

/**
 * Seals snapshot bodies before they touch disk. Snapshots hold whole request
 * bodies - exactly the content the transport encryption protects - so this
 * keeps them out of plaintext on the volume, host backups and VM snapshots.
 * It is not protection against a compromise of the running relay, which holds
 * the key in memory either way.
 */
export function createSnapshotCipher(config) {
  const keyIds = Object.keys(config.relayEncryptionKeys || {});
  if (keyIds.length === 0) {
    return null;
  }
  const keyId =
    config.relaySnapshotKeyId && config.relayEncryptionKeys[config.relaySnapshotKeyId]
      ? config.relaySnapshotKeyId
      : keyIds[0];
  const key = getEncryptionKey(config, keyId);

  return {
    seal(plaintext) {
      const encrypted = encryptAesGcm(key, plaintext);
      return JSON.stringify({
        v: 1,
        alg: AES_256_GCM,
        keyId,
        iv: encrypted.iv.toString("base64"),
        tag: encrypted.tag.toString("base64"),
        ciphertext: encrypted.ciphertext.toString("base64")
      });
    },
    open(stored) {
      let envelope;
      try {
        envelope = JSON.parse(stored);
      } catch {
        throw new Error("snapshot payload is not a valid envelope");
      }
      if (!envelope || envelope.v !== 1 || envelope.alg !== AES_256_GCM) {
        throw new Error("unsupported snapshot envelope");
      }
      return decryptAesGcm(
        getEncryptionKey(config, envelope.keyId),
        envelope.iv,
        envelope.tag,
        Buffer.from(envelope.ciphertext, "base64")
      );
    }
  };
}

function isEncryptedInit(body) {
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

/** Decrypts the init envelope, which describes the request without revealing it. */
function decryptInitMetadata(config, enc) {
  const key = getEncryptionKey(config, enc.keyId);
  const plaintext = decryptAesGcm(key, enc.iv, enc.tag, Buffer.from(enc.ciphertext, "base64"));
  return { key, metadata: JSON.parse(plaintext.toString("utf8")) };
}

function validateInitMetadata(metadata) {
  if (
    typeof metadata.method !== "string" ||
    typeof metadata.path !== "string" ||
    typeof metadata.targetUrl !== "string" ||
    typeof metadata.chunkCount !== "number" ||
    metadata.relayTransferEncoding !== TRANSFER_ENCODING_ZSTD ||
    typeof metadata.compressedBodySize !== "number" ||
    typeof metadata.bodySha256 !== "string"
  ) {
    throw new Error("invalid relay v5 init metadata");
  }
  if (metadata.baseSnapshotId !== undefined && typeof metadata.baseSnapshotId !== "string") {
    throw new Error("invalid baseSnapshotId");
  }
}

/**
 * Decompresses a relay payload. When `dictionary` is supplied the client
 * compressed the whole body against a snapshot both sides hold, which is what
 * turns a megabyte of unchanged conversation history into a few hundred bytes.
 */
function decodeRelayCompressedBody(metadata, compressedBody, dictionary = null) {
  if (metadata.relayTransferEncoding !== TRANSFER_ENCODING_ZSTD) {
    throw new Error("unsupported relay content encoding");
  }
  if (metadata.compressedBodySize && compressedBody.length !== metadata.compressedBodySize) {
    throw new Error("assembled compressed body size mismatch");
  }
  if (metadata.compressedBodySha256 && sha256Hex(compressedBody) !== metadata.compressedBodySha256) {
    throw new Error("assembled compressed body checksum mismatch");
  }

  let body;
  try {
    body = dictionary
      ? zstdDecompressSync(compressedBody, { dictionary })
      : zstdDecompressSync(compressedBody);
  } catch (error) {
    throw new Error(`invalid zstd body: ${errorMessage(error)}`);
  }

  if (typeof metadata.bodySize === "number" && metadata.bodySize && body.length !== metadata.bodySize) {
    throw new Error("assembled body size mismatch");
  }
  // The integrity gate. A wrong dictionary can still decompress into
  // plausible-looking bytes, so nothing reaches upstream without matching the
  // hash the client computed over what it meant to send.
  if (sha256Hex(body) !== metadata.bodySha256) {
    throw new Error("assembled body checksum mismatch");
  }
  return body;
}

/** Best-effort conversation id; used only to decide which snapshots to keep. */
function conversationKeyOf(bodyBuffer) {
  try {
    const parsed = JSON.parse(bodyBuffer.toString("utf8"));
    if (parsed && typeof parsed === "object") {
      if (typeof parsed.prompt_cache_key === "string") {
        return parsed.prompt_cache_key;
      }
      const metadata = parsed.client_metadata;
      if (metadata && typeof metadata === "object") {
        for (const field of ["session_id", "thread_id"]) {
          if (typeof metadata[field] === "string") {
            return metadata[field];
          }
        }
      }
    }
  } catch {
    // not JSON, or not a Codex request
  }
  return "";
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
    return new Response(null, { status: 204, headers: { "x-relay-upstream": "dropped" } });
  }

  return fetchImpl(resolved.url, {
    method: resolved.method,
    headers: resolved.headers,
    body: resolved.body,
    signal
  });
}

export function createRelayHandlers(config, dependencies) {
  const upstreamRouter = dependencies.upstreamRouter || createUpstreamRouter(config);
  const snapshotCipher = createSnapshotCipher(config);
  const store = new ChunkRequestStore(config.relayStorageDir, config.relayRequestTtlMs);
  const snapshotStore = new RelaySnapshotStore(
    config.relayStorageDir,
    config.relaySnapshotTtlMs,
    snapshotCipher,
    {
      maxSnapshots: config.relayMaxSnapshots,
      maxBytes: config.relayMaxSnapshotBytes,
      keepPerConversation: config.relayKeepPerConversation
    }
  );
  const { createAbortSignal } = dependencies;

  /**
   * Writes the upstream response back as AES-256-GCM frames. Status, content
   * type and the snapshot id go out as clear headers so the client can start
   * streaming before the body arrives; the body itself is always ciphertext.
   */
  async function streamEncryptedResponse(response, upstream, extraHeaders, encryption) {
    const headers = { ...proxyResponseHeaders(upstream), ...extraHeaders };

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
    let droppedAfter = 0;
    const bodyHash = createHash("sha256");
    if (upstream.body) {
      for await (const chunk of upstream.body) {
        const buffer = Buffer.from(chunk);
        bodyHash.update(buffer);
        // write() does not throw once the peer is gone, so a dropped frame is
        // invisible unless we check the socket ourselves.
        if (response.destroyed || response.writableEnded) {
          droppedAfter += 1;
          continue;
        }
        response.write(encodeEncryptedFrame("data", encryption.keyId, encryption.key, buffer, { seq }));
        seq += 1;
      }
    }

    const clientGone = response.destroyed || response.writableEnded;
    if (!clientGone) {
      // A terminal frame, so the client can tell a complete response from a
      // truncated one. Without it a connection dropped mid-stream decrypts
      // into a shorter but perfectly valid-looking answer.
      response.write(
        encodeEncryptedFrame(
          "end",
          encryption.keyId,
          encryption.key,
          Buffer.from(
            JSON.stringify({ dataFrames: seq - 1, bodySha256: bodyHash.digest("hex") }),
            "utf8"
          ),
          { seq }
        )
      );
      response.end();
    }
    return { frames: seq - 1, clientGone, droppedFrames: droppedAfter };
  }

  function handleUpstreamFailure(response, error, { requestId, path, abortSignal }) {
    const message = errorMessage(error);
    relayLog(config, "relay_complete_failed", {
      requestId,
      reason: message,
      error: serializeError(error),
      clientDisconnected: abortSignal.aborted
    });
    if (config.relayDebugLog) {
      logError("[relay-upstream-error]", { requestId, path, clientDisconnected: abortSignal.aborted }, error);
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

  function sendBaseUnavailable(response, requestId, baseSnapshotId) {
    relayLog(config, "relay_base_snapshot_missing", { requestId, baseSnapshotId });
    sendJson(response, 409, {
      error: {
        code: "base_snapshot_unavailable",
        baseSnapshotId,
        message: "base snapshot unavailable"
      }
    });
    return true;
  }

  async function handleInit(request, response) {
    if (!isRelayAuthorized(config, request)) {
      sendJson(response, 401, { error: { message: "relay auth failed" } });
      return true;
    }

    let body;
    let metadata;
    try {
      body = await readJsonBody(request);
      if (!isEncryptedInit(body)) {
        sendJson(response, 400, {
          error: { message: "invalid relay v5 init payload: an encrypted envelope is required" }
        });
        return true;
      }
      metadata = decryptInitMetadata(config, body.enc).metadata;
      validateInitMetadata(metadata);
    } catch (error) {
      sendJson(response, 400, { error: { message: errorMessage(error) } });
      return true;
    }

    // Checked before a single chunk is uploaded. If the base is gone the client
    // has to recompress without a dictionary, and there is no reason to make it
    // pay for the upload twice.
    const baseSnapshotId = metadata.baseSnapshotId || "";
    if (baseSnapshotId && !(await snapshotStore.hasSnapshot(baseSnapshotId))) {
      return sendBaseUnavailable(response, body.requestId, baseSnapshotId);
    }

    await store.createRequest({
      version: "v5",
      requestId: body.requestId,
      chunkCount: body.chunkCount,
      createdAt: Date.now(),
      enc: body.enc
    });
    relayLog(config, "relay_init_received", {
      requestId: body.requestId,
      chunkCount: body.chunkCount,
      keyId: body.enc.keyId,
      baseSnapshotId,
      compressedBodySize: metadata.compressedBodySize
    });
    sendJson(response, 202, { ok: true, requestId: body.requestId, version: "v5" });
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

    await store.writeChunk(
      requestId,
      index,
      encodeFrame({ type: "requestChunk", alg: AES_256_GCM, iv, tag }, chunk)
    );
    relayLog(config, "relay_chunk_received", { requestId, index, ciphertextBytes: chunk.length });
    sendJson(response, 202, { ok: true, requestId, index, bytes: chunk.length, version: "v5" });
    return true;
  }

  async function handleComplete(request, response) {
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
    let parsed;
    let responseEncryption;
    try {
      assembled = await store.assemble(body.requestId);
      if (assembled.metadata.version !== "v5") {
        throw new Error("request is not a v5 upload");
      }
      parsed = decryptInitMetadata(config, assembled.metadata.enc);
      validateInitMetadata(parsed.metadata);
      responseEncryption = {
        keyId: assembled.metadata.enc.keyId,
        key: getEncryptionKey(config, assembled.metadata.enc.keyId)
      };
    } catch (error) {
      sendJson(response, 409, { error: { message: errorMessage(error) } });
      return true;
    }

    const baseSnapshotId = parsed.metadata.baseSnapshotId || "";
    let dictionary = null;
    if (baseSnapshotId) {
      try {
        dictionary = (await snapshotStore.getSnapshot(baseSnapshotId)).body;
      } catch {
        // Evicted between init and complete.
        return sendBaseUnavailable(response, body.requestId, baseSnapshotId);
      }
    }

    let requestBody;
    try {
      requestBody = decodeRelayCompressedBody(
        parsed.metadata,
        decodeRequestChunkFrames(parsed.key, assembled.body),
        dictionary
      );
    } catch (error) {
      const message = errorMessage(error);
      sendJson(response, message.includes("checksum") ? 409 : 400, { error: { message } });
      return true;
    }

    const requestMetadata = {
      requestId: body.requestId,
      method: parsed.metadata.method,
      path: parsed.metadata.path,
      targetUrl: parsed.metadata.targetUrl,
      headers: normalizeStoredHeaders(parsed.metadata.headers)
    };

    relayLog(config, "relay_assembled", {
      requestId: body.requestId,
      path: requestMetadata.path,
      chunkCount: assembled.metadata.chunkCount,
      wireBytes: parsed.metadata.compressedBodySize,
      bodyBytes: requestBody.length,
      baseSnapshotId,
      savedRatio: Number((requestBody.length / Math.max(1, parsed.metadata.compressedBodySize)).toFixed(1))
    });

    try {
      const upstream = await sendGenericUpstream(
        fetch,
        upstreamRouter,
        config,
        requestMetadata,
        requestBody,
        abortSignal
      );

      // Only snapshot what actually reached upstream, so the two sides cannot
      // end up disagreeing about the base after a failed request.
      let snapshotMetadata = null;
      if (upstream.status >= 200 && upstream.status < 300) {
        const candidate = {
          snapshotId: `snap_${randomBytes(16).toString("hex")}`,
          createdAt: Date.now(),
          conversationKey: conversationKeyOf(requestBody),
          bodySha256: parsed.metadata.bodySha256,
          bodySize: requestBody.length,
          targetUrl: requestMetadata.targetUrl
        };
        try {
          await snapshotStore.createSnapshot(candidate, requestBody);
          snapshotMetadata = candidate;
          relayLog(config, "relay_snapshot_created", {
            requestId: body.requestId,
            snapshotId: candidate.snapshotId,
            conversationKey: candidate.conversationKey,
            bytes: requestBody.length
          });
        } catch (error) {
          relayLog(config, "relay_snapshot_skipped", {
            requestId: body.requestId,
            reason: errorMessage(error)
          });
        }
      }

      const streamed = await streamEncryptedResponse(
        response,
        upstream,
        snapshotMetadata
          ? {
              [SNAPSHOT_ID_HEADER]: snapshotMetadata.snapshotId,
              [SNAPSHOT_BODY_SHA256_HEADER]: snapshotMetadata.bodySha256
            }
          : {},
        responseEncryption
      );
      await store.remove(body.requestId);
      relayLog(config, "relay_complete_finished", {
        requestId: body.requestId,
        status: upstream.status,
        frames: streamed.frames,
        clientGone: streamed.clientGone,
        droppedFrames: streamed.droppedFrames
      });
      return true;
    } catch (error) {
      return handleUpstreamFailure(response, error, {
        requestId: body.requestId,
        path: requestMetadata.path,
        abortSignal
      });
    }
  }

  return {
    snapshotStats: () => snapshotStore.stats(),

    async maybeHandle(request, response, url) {
      // One wire protocol. The payload is always the whole request body,
      // zstd-compressed and AES-256-GCM chunked. Supplying a baseSnapshotId
      // means it was compressed against a snapshot both sides hold, which is
      // what makes an incremental turn cost a few hundred bytes instead of
      // re-uploading the entire conversation.
      if (request.method === "POST" && url.pathname === "/relay/v5/request/init") {
        relayLog(config, "relay_route_matched", { method: request.method, path: url.pathname });
        return handleInit(request, response);
      }

      const chunkMatch = /^\/relay\/v5\/request\/chunks\/([^/]+)\/(\d+)$/.exec(url.pathname);
      if (request.method === "PUT" && chunkMatch) {
        return handleChunk(request, response, chunkMatch[1], Number(chunkMatch[2]));
      }

      if (request.method === "POST" && url.pathname === "/relay/v5/request/complete") {
        relayLog(config, "relay_route_matched", { method: request.method, path: url.pathname });
        return handleComplete(request, response);
      }

      return false;
    }
  };
}
