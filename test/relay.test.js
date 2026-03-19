import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import { createRelayHandlers } from "../src/relay.js";

const TEST_KEY = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const TEST_KEY_B64 = TEST_KEY.toString("base64");

async function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

async function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function sha256Hex(content) {
  return createHash("sha256").update(content).digest("hex");
}

function encryptAesGcm(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", TEST_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    ciphertext,
    tag: tag.toString("base64")
  };
}

function decryptAesGcm(iv, tag, ciphertext) {
  const decipher = createDecipheriv("aes-256-gcm", TEST_KEY, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function gzipMetadata(bodyBuffer) {
  const compressedBody = gzipSync(bodyBuffer);
  return {
    relayTransferEncoding: "gzip",
    compressedBody,
    compressedBodySize: compressedBody.length,
    compressedBodySha256: sha256Hex(compressedBody)
  };
}

function relayMetadata(bodyBuffer, overrides = {}) {
  const gzipState = gzipMetadata(bodyBuffer);
  return {
    gzipState,
    metadata: {
      bodySize: bodyBuffer.length,
      bodySha256: sha256Hex(bodyBuffer),
      relayTransferEncoding: gzipState.relayTransferEncoding,
      compressedBodySize: gzipState.compressedBodySize,
      compressedBodySha256: gzipState.compressedBodySha256,
      ...overrides
    }
  };
}

function decodeFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (offset < buffer.length) {
    const headerLength = buffer.readUInt32BE(offset);
    offset += 4;
    const header = JSON.parse(buffer.subarray(offset, offset + headerLength).toString("utf8"));
    offset += headerLength;
    const payload = buffer.subarray(offset, offset + header.payloadLength);
    offset += header.payloadLength;
    frames.push({ header, payload });
  }
  return frames;
}

function createRelayServer(configOverrides = {}) {
  return createRelayHandlers(
    {
      relayStorageDir: configOverrides.relayStorageDir,
      relayRequestTtlMs: 60_000,
      relaySharedSecret: "secret",
      relayProtocolV2Enabled: configOverrides.relayProtocolV2Enabled ?? true,
      relayEncryptionKeys: configOverrides.relayEncryptionKeys ?? { default: TEST_KEY_B64 }
    },
    {
      createAbortSignal(_request, response) {
        assert.ok(response, "response is required for abort signal creation");
        return new AbortController().signal;
      }
    }
  );
}

test("relay handlers transparently forward assembled responses requests", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const captured = {
    url: null,
    method: null,
    headers: null,
    body: null
  };
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir });
  const originalFetch = globalThis.fetch;

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.url = String(url);
    captured.method = init.method;
    captured.headers = Object.fromEntries(new Headers(init.headers).entries());
    captured.body = Buffer.from(init.body);
    return new Response("data: hello\n\n", {
      status: 200,
      headers: {
        "content-type": "text/event-stream"
      }
    });
  };

  try {
    const originalBody = JSON.stringify({
      model: "gpt-5.4",
      stream: true,
      input: [{ role: "user", content: [{ type: "input_text", text: "hello" }] }]
    });
    const bodyBuffer = Buffer.from(originalBody, "utf8");
    const { gzipState, metadata: compressionMetadata } = relayMetadata(bodyBuffer);
    const chunkSize = Math.ceil(gzipState.compressedBody.length / 2);
    const firstChunk = gzipState.compressedBody.subarray(0, chunkSize);
    const secondChunk = gzipState.compressedBody.subarray(chunkSize);

    let response = await fetch(`${baseUrl}/relay/v1/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_1",
        method: "POST",
        path: "/v1/responses",
        targetUrl: "https://chatgpt.com/backend-api/codex/responses",
        headers: {
          authorization: "Bearer inbound",
          "x-session-id": "sess_1",
          "content-type": "application/json"
        },
        ...compressionMetadata,
        chunkCount: 2
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_1/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(firstChunk.length),
        "x-chunk-sha256": sha256Hex(firstChunk)
      },
      body: firstChunk
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_1/1`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(secondChunk.length),
        "x-chunk-sha256": sha256Hex(secondChunk)
      },
      body: secondChunk
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_1" })
    });

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "text/event-stream");
    assert.equal(await response.text(), "data: hello\n\n");
    assert.equal(captured.url, "https://chatgpt.com/backend-api/codex/responses");
    assert.equal(captured.method, "POST");
    assert.equal(captured.headers.authorization, "Bearer inbound");
    assert.equal(captured.headers["x-session-id"], "sess_1");
    assert.equal(captured.body.toString("utf8"), originalBody);
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay handlers transparently forward responses subpaths", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const captured = {
    url: null,
    method: null,
    headers: null,
    body: null
  };
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir });
  const originalFetch = globalThis.fetch;

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.url = String(url);
    captured.method = init.method;
    captured.headers = Object.fromEntries(new Headers(init.headers).entries());
    captured.body = Buffer.from(init.body);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "content-type": "application/json"
      }
    });
  };

  try {
    const originalBody = JSON.stringify({
      model: "gpt-5.4",
      stream: false,
      input: [{ role: "user", content: [{ type: "input_text", text: "hello" }] }]
    });
    const bodyBuffer = Buffer.from(originalBody, "utf8");
    const { gzipState, metadata: compressionMetadata } = relayMetadata(bodyBuffer);

    let response = await fetch(`${baseUrl}/relay/v1/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_compact",
        method: "POST",
        path: "/v1/responses/compact",
        targetUrl: "https://chatgpt.com/backend-api/codex/responses/compact",
        headers: {
          "content-type": "application/json",
          "x-session-id": "sess_compact"
        },
        ...compressionMetadata,
        chunkCount: 1
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_compact/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(gzipState.compressedBody.length),
        "x-chunk-sha256": sha256Hex(gzipState.compressedBody)
      },
      body: gzipState.compressedBody
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_compact" })
    });

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "application/json");
    assert.deepEqual(await response.json(), { ok: true });
    assert.equal(captured.url, "https://chatgpt.com/backend-api/codex/responses/compact");
    assert.equal(captured.method, "POST");
    assert.equal(captured.headers["x-session-id"], "sess_compact");
    assert.equal(captured.body.toString("utf8"), originalBody);
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay rejects chunk with bad checksum", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir });

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    let response = await fetch(`${baseUrl}/relay/v1/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_bad",
        method: "POST",
        path: "/v1/responses",
        targetUrl: "https://chatgpt.com/backend-api/codex/responses",
        headers: {},
        bodySize: 5,
        bodySha256: "",
        relayTransferEncoding: "gzip",
        compressedBodySize: 5,
        compressedBodySha256: "",
        chunkCount: 1
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_bad/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": "5",
        "x-chunk-sha256": "bad"
      },
      body: "hello"
    });

    assert.equal(response.status, 400);
    const json = await response.json();
    assert.equal(json.error.message, "chunk checksum mismatch");
  } finally {
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay generically forwards non-codex HTTP requests after reassembly", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const captured = {
    url: null,
    method: null,
    headers: null,
    body: null
  };
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir });
  const originalFetch = globalThis.fetch;

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.url = String(url);
    captured.method = init.method;
    captured.headers = Object.fromEntries(new Headers(init.headers).entries());
    if (Buffer.isBuffer(init.body)) {
      captured.body = Buffer.from(init.body);
    } else if (typeof init.body === "string") {
      captured.body = Buffer.from(init.body, "utf8");
    } else if (init.body instanceof Uint8Array) {
      captured.body = Buffer.from(init.body);
    } else {
      throw new Error(`unexpected body type: ${typeof init.body}`);
    }
    return new Response("ok", {
      status: 202,
      headers: {
        "content-type": "text/plain"
      }
    });
  };

  try {
    const originalBody = JSON.stringify({ resourceSpans: [{ scopeSpans: [] }] });
    const bodyBuffer = Buffer.from(originalBody, "utf8");
    const { gzipState, metadata: compressionMetadata } = relayMetadata(bodyBuffer);

    let response = await fetch(`${baseUrl}/relay/v1/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_metrics",
        method: "POST",
        path: "/otlp/v1/metrics",
        targetUrl: "https://ab.chatgpt.com/otlp/v1/metrics",
        headers: {
          "content-type": "application/json",
          "statsig-api-key": "client-key",
          "user-agent": "OTel-OTLP-Exporter-Rust/0.31.0",
          host: "ab.chatgpt.com"
        },
        ...compressionMetadata,
        chunkCount: 1
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_metrics/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(gzipState.compressedBody.length),
        "x-chunk-sha256": sha256Hex(gzipState.compressedBody)
      },
      body: gzipState.compressedBody
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_metrics" })
    });

    assert.equal(response.status, 202);
    assert.equal(await response.text(), "ok");
    assert.equal(captured.url, "https://ab.chatgpt.com/otlp/v1/metrics");
    assert.equal(captured.method, "POST");
    assert.equal(captured.headers["content-type"], "application/json");
    assert.equal(captured.headers["statsig-api-key"], "client-key");
    assert.equal(captured.headers["user-agent"], "OTel-OTLP-Exporter-Rust/0.31.0");
    assert.equal(captured.headers.host, undefined);
    assert.equal(captured.body.toString("utf8"), originalBody);
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay forwards upstream content-encoding headers for v1 requests", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-encoding-v1-"));
  const captured = {
    headers: null,
    body: null
  };
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir });
  const originalFetch = globalThis.fetch;

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.headers = Object.fromEntries(new Headers(init.headers).entries());
    captured.body = Buffer.from(init.body);
    return new Response("ok", { status: 200 });
  };

  try {
    const originalBody = Buffer.from(JSON.stringify({ ok: true }), "utf8");
    const encodedBody = gzipSync(originalBody);
    const { gzipState, metadata: compressionMetadata } = relayMetadata(encodedBody);

    let response = await fetch(`${baseUrl}/relay/v1/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_content_encoding_v1",
        method: "POST",
        path: "/v1/responses",
        targetUrl: "https://chatgpt.com/backend-api/codex/responses",
        headers: {
          "content-type": "application/json",
          "content-encoding": "gzip"
        },
        ...compressionMetadata,
        chunkCount: 1
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_content_encoding_v1/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(gzipState.compressedBody.length),
        "x-chunk-sha256": sha256Hex(gzipState.compressedBody)
      },
      body: gzipState.compressedBody
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_content_encoding_v1" })
    });

    assert.equal(response.status, 200);
    assert.equal(await response.text(), "ok");
    assert.equal(captured.headers["content-encoding"], "gzip");
    assert.equal(captured.headers["content-type"], "application/json");
    assert.deepEqual(captured.body, encodedBody);
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay v2 decrypts encrypted request chunks and forwards upstream", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-v2-"));
  const captured = {
    url: null,
    method: null,
    headers: null,
    body: null
  };
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir, relayProtocolV2Enabled: true });
  const originalFetch = globalThis.fetch;

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.url = String(url);
    captured.method = init.method;
    captured.headers = Object.fromEntries(new Headers(init.headers).entries());
    captured.body = Buffer.from(init.body);
    return new Response(JSON.stringify({ ok: true, mode: "v2" }), {
      status: 201,
      headers: {
        "content-type": "application/json"
      }
    });
  };

  try {
    const originalBody = JSON.stringify({
      model: "gpt-5.4",
      stream: false,
      input: [{ role: "user", content: [{ type: "input_text", text: "hello from v2" }] }]
    });
    const bodyBuffer = Buffer.from(originalBody, "utf8");
    const { gzipState, metadata: compressionMetadata } = relayMetadata(bodyBuffer);
    const metadata = {
      method: "POST",
      path: "/v1/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: {
        authorization: "Bearer inbound-v2",
        "x-session-id": "sess_v2",
        "content-type": "application/json"
      },
      ...compressionMetadata,
      chunkCount: 2
    };
    const encryptedMetadata = encryptAesGcm(Buffer.from(JSON.stringify(metadata), "utf8"));

    let response = await fetch(`${baseUrl}/relay/v2/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_v2",
        chunkCount: 2,
        enc: {
          alg: "aes-256-gcm",
          keyId: "default",
          iv: encryptedMetadata.iv,
          tag: encryptedMetadata.tag,
          ciphertext: encryptedMetadata.ciphertext.toString("base64")
        }
      })
    });
    assert.equal(response.status, 202);

    const midpoint = Math.ceil(gzipState.compressedBody.length / 2);
    const parts = [
      gzipState.compressedBody.subarray(0, midpoint),
      gzipState.compressedBody.subarray(midpoint)
    ];
    for (const [index, part] of parts.entries()) {
      const encryptedChunk = encryptAesGcm(part);
      response = await fetch(`${baseUrl}/relay/v2/chunked/chunks/req_v2/${index}`, {
        method: "PUT",
        headers: {
          "x-relay-secret": "secret",
          "x-chunk-iv": encryptedChunk.iv,
          "x-chunk-tag": encryptedChunk.tag,
          "x-chunk-size": String(encryptedChunk.ciphertext.length),
          "x-chunk-sha256": sha256Hex(encryptedChunk.ciphertext)
        },
        body: encryptedChunk.ciphertext
      });
      assert.equal(response.status, 202);
    }

    response = await fetch(`${baseUrl}/relay/v2/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_v2" })
    });

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-relay-response-encrypted"), "aes-256-gcm-frame-v1");
    assert.equal(captured.url, "https://chatgpt.com/backend-api/codex/responses");
    assert.equal(captured.method, "POST");
    assert.equal(captured.headers.authorization, "Bearer inbound-v2");
    assert.equal(captured.headers["x-session-id"], "sess_v2");
    assert.equal(captured.body.toString("utf8"), originalBody);

    const encryptedResponseBody = Buffer.from(await response.arrayBuffer());
    const frames = decodeFrames(encryptedResponseBody);
    assert.equal(frames[0].header.type, "meta");
    const metaPlaintext = JSON.parse(
      decryptAesGcm(frames[0].header.iv, frames[0].header.tag, frames[0].payload).toString("utf8")
    );
    assert.equal(metaPlaintext.status, 201);
    assert.equal(metaPlaintext.headers["content-type"], "application/json");
    const dataPlaintext = Buffer.concat(
      frames.slice(1).map((frame) => decryptAesGcm(frame.header.iv, frame.header.tag, frame.payload))
    );
    assert.deepEqual(JSON.parse(dataPlaintext.toString("utf8")), { ok: true, mode: "v2" });
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay v2 forwards upstream content-encoding headers", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-encoding-v2-"));
  const captured = {
    headers: null,
    body: null
  };
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir, relayProtocolV2Enabled: true });
  const originalFetch = globalThis.fetch;

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.headers = Object.fromEntries(new Headers(init.headers).entries());
    captured.body = Buffer.from(init.body);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "content-type": "application/json"
      }
    });
  };

  try {
    const originalBody = Buffer.from(JSON.stringify({ transport: "relay-v2" }), "utf8");
    const encodedBody = gzipSync(originalBody);
    const { gzipState, metadata: compressionMetadata } = relayMetadata(encodedBody);
    const metadata = {
      method: "POST",
      path: "/v1/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: {
        "content-type": "application/json",
        "content-encoding": "gzip"
      },
      ...compressionMetadata,
      chunkCount: 1
    };
    const encryptedMetadata = encryptAesGcm(Buffer.from(JSON.stringify(metadata), "utf8"));

    let response = await fetch(`${baseUrl}/relay/v2/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_content_encoding_v2",
        chunkCount: 1,
        enc: {
          alg: "aes-256-gcm",
          keyId: "default",
          iv: encryptedMetadata.iv,
          tag: encryptedMetadata.tag,
          ciphertext: encryptedMetadata.ciphertext.toString("base64")
        }
      })
    });
    assert.equal(response.status, 202);

    const encryptedChunk = encryptAesGcm(gzipState.compressedBody);
    response = await fetch(`${baseUrl}/relay/v2/chunked/chunks/req_content_encoding_v2/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-iv": encryptedChunk.iv,
        "x-chunk-tag": encryptedChunk.tag,
        "x-chunk-size": String(encryptedChunk.ciphertext.length),
        "x-chunk-sha256": sha256Hex(encryptedChunk.ciphertext)
      },
      body: encryptedChunk.ciphertext
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v2/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_content_encoding_v2" })
    });

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-relay-response-encrypted"), "aes-256-gcm-frame-v1");
    assert.equal(captured.headers["content-encoding"], "gzip");
    assert.equal(captured.headers["content-type"], "application/json");
    assert.deepEqual(captured.body, encodedBody);
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay v2 rejects unknown encryption key", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-v2-"));
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir, relayProtocolV2Enabled: true });

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const encryptedMetadata = encryptAesGcm(
      Buffer.from(
        JSON.stringify({
          method: "POST",
          path: "/v1/responses",
          targetUrl: "https://chatgpt.com/backend-api/codex/responses",
          headers: {},
          bodySize: 0,
          bodySha256: "",
          relayTransferEncoding: "gzip",
          compressedBodySize: 20,
          compressedBodySha256: "",
          chunkCount: 0
        }),
        "utf8"
      )
    );
    const response = await fetch(`${baseUrl}/relay/v2/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_v2_bad_key",
        chunkCount: 0,
        enc: {
          alg: "aes-256-gcm",
          keyId: "missing",
          iv: encryptedMetadata.iv,
          tag: encryptedMetadata.tag,
          ciphertext: encryptedMetadata.ciphertext.toString("base64")
        }
      })
    });

    assert.equal(response.status, 400);
    const json = await response.json();
    assert.match(json.error.message, /unknown encryption keyId/);
  } finally {
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay accepts legacy contentEncodingApplied metadata", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-legacy-"));
  const captured = {
    body: null
  };
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir });
  const originalFetch = globalThis.fetch;

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.body = Buffer.from(init.body);
    return new Response("ok", { status: 200 });
  };

  try {
    const originalBody = Buffer.from("legacy-body", "utf8");
    const compressedBody = gzipSync(originalBody);

    let response = await fetch(`${baseUrl}/relay/v1/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_legacy_metadata",
        method: "POST",
        path: "/v1/responses",
        targetUrl: "https://chatgpt.com/backend-api/codex/responses",
        headers: {
          "content-type": "application/octet-stream"
        },
        bodySize: originalBody.length,
        bodySha256: sha256Hex(originalBody),
        contentEncodingApplied: "gzip",
        compressedBodySize: compressedBody.length,
        compressedBodySha256: sha256Hex(compressedBody),
        chunkCount: 1
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_legacy_metadata/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(compressedBody.length),
        "x-chunk-sha256": sha256Hex(compressedBody)
      },
      body: compressedBody
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_legacy_metadata" })
    });

    assert.equal(response.status, 200);
    assert.equal(await response.text(), "ok");
    assert.deepEqual(captured.body, originalBody);
  } finally {
    globalThis.fetch = originalFetch;
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay rejects invalid gzip body during complete", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-gzip-"));
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir });

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await listen(server);
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const invalidGzip = Buffer.from("not-gzip", "utf8");
    let response = await fetch(`${baseUrl}/relay/v1/chunked/init`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({
        requestId: "req_bad_gzip",
        method: "POST",
        path: "/v1/responses",
        targetUrl: "https://chatgpt.com/backend-api/codex/responses",
        headers: {
          "content-type": "application/json"
        },
        bodySize: 5,
        bodySha256: sha256Hex(Buffer.from("hello", "utf8")),
        relayTransferEncoding: "gzip",
        compressedBodySize: invalidGzip.length,
        compressedBodySha256: sha256Hex(invalidGzip),
        chunkCount: 1
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_bad_gzip/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(invalidGzip.length),
        "x-chunk-sha256": sha256Hex(invalidGzip)
      },
      body: invalidGzip
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/complete`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-relay-secret": "secret"
      },
      body: JSON.stringify({ requestId: "req_bad_gzip" })
    });

    assert.equal(response.status, 400);
    const json = await response.json();
    assert.equal(json.error.message, "invalid gzip body");
  } finally {
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});
