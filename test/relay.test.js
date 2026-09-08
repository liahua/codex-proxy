import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import { createRelayHandlers } from "../src/relay.js";

const TEST_KEY = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const TEST_KEY_B64 = TEST_KEY.toString("base64");
const SECRET = "secret";
const TARGET_URL = "https://chatgpt.com/backend-api/codex/responses";

// ---------------------------------------------------------------------------
// crypto + framing helpers, mirroring what the mitm addon does on the client
// ---------------------------------------------------------------------------

function sha256Hex(content) {
  return createHash("sha256").update(content).digest("hex");
}

function stableJsonStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableJsonStringify).join(",")}]`;
  }
  const entries = Object.entries(value)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableJsonStringify(v)}`).join(",")}}`;
}

function canonicalJsonHash(value) {
  return sha256Hex(Buffer.from(stableJsonStringify(value), "utf8"));
}

function encryptAesGcm(plaintext, key = TEST_KEY) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext
  };
}

function decryptAesGcm(iv, tag, ciphertext, key = TEST_KEY) {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function decodeFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (offset < buffer.length) {
    const headerLength = buffer.readUInt32BE(offset);
    offset += 4;
    const header = JSON.parse(buffer.subarray(offset, offset + headerLength).toString("utf8"));
    offset += headerLength;
    frames.push({ header, payload: buffer.subarray(offset, offset + header.payloadLength) });
    offset += header.payloadLength;
  }
  return frames;
}

// ---------------------------------------------------------------------------
// v4 client, speaking the same wire protocol as the mitm addon
// ---------------------------------------------------------------------------

/** Decrypts the relay's response frames back into status/headers/body. */
async function decodeRelayResponse(response) {
  if (response.headers.get("x-relay-response-encrypted") !== "aes-256-gcm-frame-v1") {
    return { encrypted: false, status: response.status, headers: {}, body: await response.text() };
  }
  const raw = Buffer.from(await response.arrayBuffer());
  let status = response.status;
  let headers = {};
  const chunks = [];
  for (const frame of decodeFrames(raw)) {
    const plaintext = decryptAesGcm(frame.header.iv, frame.header.tag, frame.payload);
    if (frame.header.type === "meta") {
      const meta = JSON.parse(plaintext.toString("utf8"));
      status = meta.status;
      headers = meta.headers;
      continue;
    }
    assert.equal(frame.header.type, "data");
    chunks.push(plaintext);
  }
  return { encrypted: true, status, headers, body: Buffer.concat(chunks).toString("utf8"), raw };
}

function createRelayClient(baseUrl, { secret = SECRET, keyId = "default" } = {}) {
  const authHeaders = secret ? { "x-relay-secret": secret } : {};

  function encryptedEnvelope(requestId, chunkCount, metadata) {
    const encrypted = encryptAesGcm(Buffer.from(JSON.stringify({ ...metadata, chunkCount }), "utf8"));
    return {
      requestId,
      chunkCount,
      enc: {
        alg: "aes-256-gcm",
        keyId,
        iv: encrypted.iv,
        tag: encrypted.tag,
        ciphertext: encrypted.ciphertext.toString("base64")
      }
    };
  }

  async function putChunks(kind, requestId, compressed, chunkSize) {
    const results = [];
    for (let offset = 0, index = 0; offset < compressed.length; offset += chunkSize, index += 1) {
      const encrypted = encryptAesGcm(compressed.subarray(offset, offset + chunkSize));
      results.push(
        await fetch(`${baseUrl}/relay/v4/${kind}/chunks/${requestId}/${index}`, {
          method: "PUT",
          headers: {
            ...authHeaders,
            "content-type": "application/octet-stream",
            "x-chunk-iv": encrypted.iv,
            "x-chunk-tag": encrypted.tag,
            "x-chunk-size": String(encrypted.ciphertext.length),
            "x-chunk-sha256": sha256Hex(encrypted.ciphertext)
          },
          body: encrypted.ciphertext
        })
      );
    }
    return results;
  }

  function chunkCountFor(length, chunkSize) {
    return Math.max(1, Math.ceil(length / chunkSize));
  }

  async function uploadEncrypted(kind, requestId, metadata, payloadBuffer, chunkSize) {
    const compressed = gzipSync(payloadBuffer);
    const fullMetadata = {
      ...metadata,
      relayTransferEncoding: "gzip",
      bodySize: payloadBuffer.length,
      bodySha256: sha256Hex(payloadBuffer),
      compressedBodySize: compressed.length,
      compressedBodySha256: sha256Hex(compressed)
    };
    const init = await fetch(`${baseUrl}/relay/v4/${kind}/init`, {
      method: "POST",
      headers: { ...authHeaders, "content-type": "application/json" },
      body: JSON.stringify(
        encryptedEnvelope(requestId, chunkCountFor(compressed.length, chunkSize), fullMetadata)
      )
    });
    const chunks = await putChunks(kind, requestId, compressed, chunkSize);
    return { init, chunks };
  }

  return {
    /** Uploads a whole request body as encrypted gzip chunks. */
    uploadFull(requestId, bodyObject, { chunkSize = 1 << 20, headers = {}, path, targetUrl } = {}) {
      return uploadEncrypted(
        "full",
        requestId,
        {
          version: "v4-full",
          method: "POST",
          path: path ?? "/backend-api/codex/responses",
          targetUrl: targetUrl ?? TARGET_URL,
          headers: { "content-type": "application/json", ...headers }
        },
        Buffer.from(JSON.stringify(bodyObject), "utf8"),
        chunkSize
      );
    },

    /** Uploads a delta or refs payload as encrypted gzip chunks. */
    uploadPayload(kind, requestId, payload, { chunkSize = 1 << 20 } = {}) {
      return uploadEncrypted(
        kind,
        requestId,
        { version: `v4-${kind}-chunked` },
        Buffer.from(JSON.stringify(payload), "utf8"),
        chunkSize
      );
    },

    async complete(kind, requestId) {
      const response = await fetch(`${baseUrl}/relay/v4/${kind}/complete`, {
        method: "POST",
        headers: { ...authHeaders, "content-type": "application/json" },
        body: JSON.stringify({ requestId })
      });
      return { response, decoded: await decodeRelayResponse(response) };
    }
  };
}

// ---------------------------------------------------------------------------
// server harness
// ---------------------------------------------------------------------------

function createRelayServer(configOverrides = {}) {
  return createRelayHandlers(
    {
      relayStorageDir: configOverrides.relayStorageDir,
      relayRequestTtlMs: 60_000,
      relaySharedSecret: configOverrides.relaySharedSecret ?? SECRET,
      relayEncryptionKeys: configOverrides.relayEncryptionKeys ?? { default: TEST_KEY_B64 },
      relaySnapshotTtlMs: 60_000,
      relayResponseSnapshotTtlMs: 60_000,
      relayResponseRefMinChars: configOverrides.relayResponseRefMinChars ?? 8,
      relayDebugLog: configOverrides.relayDebugLog ?? false,
      relayUpstreamMode: configOverrides.relayUpstreamMode ?? "passthrough",
      cpaBaseUrl: configOverrides.cpaBaseUrl ?? "",
      cpaApiKey: configOverrides.cpaApiKey ?? "",
      cpaModelMap: configOverrides.cpaModelMap ?? {},
      cpaForceModel: configOverrides.cpaForceModel ?? "",
      cpaDropUnmatched: configOverrides.cpaDropUnmatched ?? false
    },
    {
      createAbortSignal(_request, response) {
        assert.ok(response, "response is required for abort signal creation");
        return new AbortController().signal;
      }
    }
  );
}

/**
 * Boots a relay on a random port with a stubbed upstream, runs `run`, and always
 * tears both down. `captured` collects every upstream call the relay made.
 */
async function withRelay(configOverrides, run, upstreamFactory) {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir, ...configOverrides });
  const captured = [];

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.push({
      url: String(url),
      method: init.method,
      headers: Object.fromEntries(new Headers(init.headers).entries()),
      body: init.body ? Buffer.from(init.body) : Buffer.alloc(0)
    });
    return upstreamFactory
      ? upstreamFactory(captured.length - 1)
      : new Response("data: ok\n\n", {
          status: 200,
          headers: { "content-type": "text/event-stream" }
        });
  };

  try {
    await run({ baseUrl, captured, storageDir, client: createRelayClient(baseUrl) });
  } finally {
    globalThis.fetch = originalFetch;
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    await rm(storageDir, { recursive: true, force: true });
  }
}

function codexBody(input, overrides = {}) {
  return { model: "gpt-5.4", stream: true, input, ...overrides };
}

function userItem(text) {
  return { role: "user", content: [{ type: "input_text", text }] };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test("v4 full upload decrypts, reassembles and forwards the original body", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const body = codexBody([userItem("hello")]);
    const { init } = await client.uploadFull("req_full", body, {
      headers: { "x-session-id": "sess_full" }
    });
    assert.equal(init.status, 202);

    const { decoded } = await client.complete("full", "req_full");
    assert.equal(decoded.status, 200);
    assert.equal(decoded.body, "data: ok\n\n");

    assert.equal(captured.length, 1);
    assert.equal(captured[0].url, TARGET_URL);
    assert.deepEqual(JSON.parse(captured[0].body.toString("utf8")), body);
    assert.equal(captured[0].headers["x-session-id"], "sess_full");
  });
});

test("v4 responses are always encrypted frames, never plaintext", async () => {
  await withRelay(
    {},
    async ({ client }) => {
      await client.uploadFull("req_enc", codexBody([userItem("hello")]));
      const { response, decoded } = await client.complete("full", "req_enc");

      assert.equal(response.headers.get("x-relay-response-encrypted"), "aes-256-gcm-frame-v1");
      assert.equal(response.headers.get("content-type"), "application/octet-stream");
      assert.equal(decoded.encrypted, true);
      assert.ok(
        !decoded.raw.includes(Buffer.from("top-secret-answer", "utf8")),
        "the response body must not appear in plaintext on the wire"
      );
      assert.equal(decoded.body, "data: top-secret-answer\n\n");
      // upstream status and headers survive inside the encrypted meta frame
      assert.equal(decoded.status, 200);
      assert.equal(decoded.headers["content-type"], "text/event-stream");
      assert.ok(decoded.headers["x-relay-snapshot-id"]);
    },
    () =>
      new Response("data: top-secret-answer\n\n", {
        status: 200,
        headers: { "content-type": "text/event-stream" }
      })
  );
});

test("v4 delta rebuilds the full body from a snapshot without re-uploading history", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const firstInput = [userItem("hello")];
    const firstBody = codexBody(firstInput);
    await client.uploadFull("req_base", firstBody);
    const first = await client.complete("full", "req_base");
    const snapshotId = first.decoded.headers["x-relay-snapshot-id"];
    const snapshotSha = first.decoded.headers["x-relay-snapshot-body-sha256"];
    assert.ok(snapshotId);
    assert.equal(snapshotSha, canonicalJsonHash(firstBody));

    const secondInput = [
      ...firstInput,
      { role: "assistant", content: [{ type: "output_text", text: "hi" }] },
      userItem("continue")
    ];
    const secondBody = codexBody(secondInput);
    const delta = {
      requestId: "req_delta",
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: TARGET_URL,
      headers: { "content-type": "application/json" },
      baseSnapshotId: snapshotId,
      baseBodySha256: snapshotSha,
      bodyFields: { model: secondBody.model, stream: secondBody.stream },
      appendInputItems: secondInput.slice(firstInput.length),
      canonicalBodySha256: canonicalJsonHash(secondBody)
    };

    const { init } = await client.uploadPayload("delta", "req_delta", delta);
    assert.equal(init.status, 202);

    const { decoded } = await client.complete("delta", "req_delta");
    assert.equal(decoded.status, 200);
    assert.equal(captured.length, 2);
    assert.deepEqual(JSON.parse(captured[1].body.toString("utf8")), secondBody);

    // what went over the wire never contained the first turn's text
    assert.ok(!JSON.stringify(delta).includes("hello"), "history must not be re-sent in the delta");
  });
});

test("v4 refs expand stored response text server-side", async () => {
  const previousResponseText = "previous assistant response copied into the next request";
  await withRelay(
    { relayResponseRefMinChars: 8 },
    async ({ captured, client }) => {
      await client.uploadFull("req_ref_base", codexBody([userItem("hello")]));
      const first = await client.complete("full", "req_ref_base");
      const responseSnapshotId = first.decoded.headers["x-relay-response-snapshot-id"];
      assert.ok(responseSnapshotId);

      const expandedBody = codexBody([
        { role: "assistant", content: [{ type: "output_text", text: previousResponseText }] },
        userItem("continue")
      ]);
      const templatedBody = {
        ...expandedBody,
        input: [
          {
            role: "assistant",
            content: [
              {
                type: "output_text",
                text: {
                  $relayRef: {
                    type: "responseText",
                    snapshotId: responseSnapshotId,
                    sha256: sha256Hex(Buffer.from(previousResponseText, "utf8"))
                  }
                }
              }
            ]
          },
          expandedBody.input[1]
        ]
      };

      const { init } = await client.uploadPayload("refs", "req_refs", {
        requestId: "req_refs",
        method: "POST",
        path: "/backend-api/codex/responses",
        targetUrl: TARGET_URL,
        headers: { "content-type": "application/json" },
        bodyTemplate: templatedBody,
        canonicalBodySha256: canonicalJsonHash(expandedBody)
      });
      assert.equal(init.status, 202);

      const { decoded } = await client.complete("refs", "req_refs");
      assert.equal(decoded.status, 200);
      assert.equal(captured.length, 2);
      assert.deepEqual(JSON.parse(captured[1].body.toString("utf8")), expandedBody);
    },
    () =>
      new Response(`data: ${JSON.stringify({ output: previousResponseText })}\n\n`, {
        status: 200,
        headers: { "content-type": "text/event-stream" }
      })
  );
});

test("v4 splits and reassembles a body across many chunks", async () => {
  await withRelay({}, async ({ captured, client }) => {
    // incompressible payload, so gzip cannot collapse it back into one chunk
    const body = codexBody([userItem(randomBytes(150_000).toString("base64"))]);
    const { chunks } = await client.uploadFull("req_big", body, { chunkSize: 20 * 1024 });
    assert.ok(chunks.length > 1, "expected the body to be split");
    for (const chunk of chunks) {
      assert.equal(chunk.status, 202);
    }

    const { decoded } = await client.complete("full", "req_big");
    assert.equal(decoded.status, 200);
    assert.deepEqual(JSON.parse(captured[0].body.toString("utf8")), body);
  });
});

test("relay rejects a chunk whose checksum does not match", async () => {
  await withRelay({}, async ({ baseUrl, client }) => {
    await client.uploadFull("req_bad", codexBody([userItem("hello")]));
    const response = await fetch(`${baseUrl}/relay/v4/full/chunks/req_bad/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": SECRET,
        "x-chunk-iv": Buffer.alloc(12).toString("base64"),
        "x-chunk-tag": Buffer.alloc(16).toString("base64"),
        "x-chunk-size": "4",
        "x-chunk-sha256": sha256Hex(Buffer.from("nope"))
      },
      body: Buffer.from("evil")
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error.message, /checksum mismatch/);
  });
});

test("relay rejects chunks with no encryption headers", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/relay/v4/full/chunks/req_x/0`, {
      method: "PUT",
      headers: { "x-relay-secret": SECRET },
      body: Buffer.from("plaintext")
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error.message, /missing chunk encryption headers/);
  });
});

test("relay rejects an unencrypted init payload on every route", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    for (const kind of ["full", "delta", "refs"]) {
      const response = await fetch(`${baseUrl}/relay/v4/${kind}/init`, {
        method: "POST",
        headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
        body: JSON.stringify({ requestId: "req_plain", method: "POST", path: "/x", targetUrl: TARGET_URL })
      });
      assert.equal(response.status, 400, `${kind} init should reject plaintext`);
      assert.match((await response.json()).error.message, /encrypted envelope is required/);
    }
  });
});

test("relay rejects an unknown encryption key id", async () => {
  await withRelay({ relayEncryptionKeys: { other: TEST_KEY_B64 } }, async ({ baseUrl }) => {
    const encrypted = encryptAesGcm(Buffer.from("{}", "utf8"));
    const response = await fetch(`${baseUrl}/relay/v4/full/init`, {
      method: "POST",
      headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
      body: JSON.stringify({
        requestId: "req_key",
        chunkCount: 1,
        enc: {
          alg: "aes-256-gcm",
          keyId: "default",
          iv: encrypted.iv,
          tag: encrypted.tag,
          ciphertext: encrypted.ciphertext.toString("base64")
        }
      })
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error.message, /unknown encryption keyId/);
  });
});

test("relay rejects calls without the shared secret", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    for (const [path, method] of [
      ["/relay/v4/full/init", "POST"],
      ["/relay/v4/full/chunks/req/0", "PUT"],
      ["/relay/v4/full/complete", "POST"],
      ["/relay/v4/delta/init", "POST"],
      ["/relay/v4/delta/complete", "POST"],
      ["/relay/v4/refs/init", "POST"],
      ["/relay/v4/refs/complete", "POST"]
    ]) {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: { "content-type": "application/json" },
        body: method === "POST" ? "{}" : Buffer.alloc(0)
      });
      assert.equal(response.status, 401, `${method} ${path} should require the secret`);
    }
  });
});

test("legacy v1 and v2 routes are gone", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    for (const path of [
      "/relay/v1/chunked/init",
      "/relay/v1/chunked/complete",
      "/relay/v2/chunked/init",
      "/relay/v2/chunked/complete"
    ]) {
      const response = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
        body: "{}"
      });
      assert.equal(response.status, 404, `${path} should no longer be routed`);
    }
  });
});

test("relay rejects a delta whose base snapshot is unknown", async () => {
  await withRelay({}, async ({ client }) => {
    await client.uploadPayload("delta", "req_orphan", {
      requestId: "req_orphan",
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: TARGET_URL,
      headers: {},
      baseSnapshotId: "snap_missing",
      baseBodySha256: "0".repeat(64),
      bodyFields: { model: "gpt-5.4" },
      appendInputItems: [userItem("continue")]
    });
    const { response } = await client.complete("delta", "req_orphan");
    assert.equal(response.status, 409);
  });
});

test("relay rejects a tampered delta whose rebuilt body fails its checksum", async () => {
  await withRelay({}, async ({ client }) => {
    await client.uploadFull("req_tamper_base", codexBody([userItem("hello")]));
    const first = await client.complete("full", "req_tamper_base");

    await client.uploadPayload("delta", "req_tamper", {
      requestId: "req_tamper",
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: TARGET_URL,
      headers: {},
      baseSnapshotId: first.decoded.headers["x-relay-snapshot-id"],
      baseBodySha256: first.decoded.headers["x-relay-snapshot-body-sha256"],
      bodyFields: { model: "gpt-5.4", stream: true },
      appendInputItems: [userItem("continue")],
      canonicalBodySha256: "0".repeat(64)
    });

    const { response } = await client.complete("delta", "req_tamper");
    assert.equal(response.status, 409);
  });
});

test("relay reports an upstream failure as 502 rather than hanging", async () => {
  await withRelay(
    {},
    async ({ client }) => {
      await client.uploadFull("req_502", codexBody([userItem("hello")]));
      const { response, decoded } = await client.complete("full", "req_502");
      assert.equal(response.status, 502);
      assert.match(JSON.parse(decoded.body).error.message, /upstream exploded/);
    },
    () => {
      throw new Error("upstream exploded");
    }
  );
});

test("cpa mode retargets the reassembled request at CPA with its own api key", async () => {
  await withRelay(
    {
      relayUpstreamMode: "cpa",
      cpaBaseUrl: "http://cli-proxy-api:8317",
      cpaApiKey: "cpa-key",
      cpaModelMap: { "gpt-5.1-codex": "gpt-5.5" }
    },
    async ({ captured, client }) => {
      const body = codexBody([userItem("hello")], { model: "gpt-5.1-codex" });
      await client.uploadFull("req_cpa", body, {
        headers: {
          authorization: "Bearer stale-chatgpt-token",
          "chatgpt-account-id": "acct_123",
          "x-session-id": "sess_cpa"
        }
      });

      const { decoded } = await client.complete("full", "req_cpa");
      assert.equal(decoded.status, 200);

      assert.equal(captured.length, 1);
      assert.equal(captured[0].url, "http://cli-proxy-api:8317/v1/responses");
      assert.equal(captured[0].headers.authorization, "Bearer cpa-key");
      assert.equal(captured[0].headers["chatgpt-account-id"], undefined);
      assert.equal(captured[0].headers["x-session-id"], "sess_cpa");
      assert.deepEqual(JSON.parse(captured[0].body.toString("utf8")), { ...body, model: "gpt-5.5" });
    }
  );
});

test("cpa mode can drop non-codex telemetry instead of relaying it", async () => {
  await withRelay(
    {
      relayUpstreamMode: "cpa",
      cpaBaseUrl: "http://cli-proxy-api:8317",
      cpaApiKey: "cpa-key",
      cpaDropUnmatched: true
    },
    async ({ captured, client }) => {
      await client.uploadFull(
        "req_metrics",
        { metrics: [] },
        { path: "/otlp/v1/metrics", targetUrl: "https://ab.chatgpt.com/otlp/v1/metrics" }
      );

      const { decoded } = await client.complete("full", "req_metrics");
      assert.equal(decoded.status, 204);
      assert.equal(captured.length, 0, "telemetry must not reach any upstream");
    }
  );
});

test("relay never forwards the upstream content-encoding it already decoded", async () => {
  await withRelay(
    {},
    async ({ client }) => {
      await client.uploadFull("req_ce", codexBody([userItem("hello")]));
      const { decoded } = await client.complete("full", "req_ce");

      // fetch() decompressed the body, so claiming it is still gzipped would
      // make the client fail to parse a perfectly good response.
      assert.equal(decoded.headers["content-encoding"], undefined);
      assert.equal(decoded.headers["content-length"], undefined);
      assert.equal(decoded.headers["content-type"], "text/event-stream");
      assert.equal(decoded.body, "data: ok\n\n");
    },
    () =>
      new Response("data: ok\n\n", {
        status: 200,
        headers: {
          "content-type": "text/event-stream",
          "content-encoding": "gzip",
          "content-length": "999"
        }
      })
  );
});

test("snapshots are encrypted at rest, not plaintext on the volume", async () => {
  const secretText = "a-very-private-line-from-the-conversation";
  const responseText = "an equally private assistant reply that refs could reuse";

  await withRelay(
    { relayResponseRefMinChars: 8 },
    async ({ client, storageDir }) => {
      await client.uploadFull("req_at_rest", codexBody([userItem(secretText)]));
      const { decoded } = await client.complete("full", "req_at_rest");
      assert.equal(decoded.status, 200);
      assert.ok(decoded.headers["x-relay-snapshot-id"]);

      const offenders = [];
      async function walk(dir) {
        let entries;
        try {
          entries = await readdir(dir, { withFileTypes: true });
        } catch {
          return; // the relay cleans finished requests up underneath us
        }
        for (const entry of entries) {
          const full = join(dir, entry.name);
          if (entry.isDirectory()) {
            await walk(full);
            continue;
          }
          let content;
          try {
            content = await readFile(full, "utf8");
          } catch {
            continue;
          }
          if (content.includes(secretText) || content.includes(responseText)) {
            offenders.push(full);
          }
        }
      }
      await walk(storageDir);
      assert.deepEqual(offenders, [], `plaintext found on disk: ${offenders.join(", ")}`);

      const snapshotIds = await readdir(join(storageDir, "snapshots"));
      const envelope = JSON.parse(
        await readFile(join(storageDir, "snapshots", snapshotIds[0], "body.json"), "utf8")
      );
      assert.equal(envelope.v, 1);
      assert.equal(envelope.alg, "aes-256-gcm");
      assert.ok(envelope.ciphertext);
    },
    () =>
      new Response(`data: ${JSON.stringify({ output: responseText })}\n\n`, {
        status: 200,
        headers: { "content-type": "text/event-stream" }
      })
  );
});

test("an encrypted snapshot still rebuilds a delta correctly", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const firstInput = [userItem("hello")];
    const firstBody = codexBody(firstInput);
    await client.uploadFull("req_sealed_base", firstBody);
    const first = await client.complete("full", "req_sealed_base");

    const secondInput = [...firstInput, userItem("continue")];
    const secondBody = codexBody(secondInput);
    await client.uploadPayload("delta", "req_sealed_delta", {
      requestId: "req_sealed_delta",
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: TARGET_URL,
      headers: { "content-type": "application/json" },
      baseSnapshotId: first.decoded.headers["x-relay-snapshot-id"],
      baseBodySha256: first.decoded.headers["x-relay-snapshot-body-sha256"],
      bodyFields: { model: secondBody.model, stream: secondBody.stream },
      appendInputItems: secondInput.slice(firstInput.length),
      canonicalBodySha256: canonicalJsonHash(secondBody)
    });

    const { decoded } = await client.complete("delta", "req_sealed_delta");
    assert.equal(decoded.status, 200);
    assert.deepEqual(JSON.parse(captured[1].body.toString("utf8")), secondBody);
  });
});
