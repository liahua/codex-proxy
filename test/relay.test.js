import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { zstdCompressSync } from "node:zlib";
import { createRelayHandlers } from "../src/relay.js";

const TEST_KEY = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const TEST_KEY_B64 = TEST_KEY.toString("base64");
const SECRET = "secret";
const TARGET_URL = "https://codex.liahuas.top/v1/responses";

// ---------------------------------------------------------------------------
// crypto + framing, mirroring what the mitm addon does on the client
// ---------------------------------------------------------------------------

function sha256Hex(content) {
  return createHash("sha256").update(content).digest("hex");
}

function encryptAesGcm(plaintext, key = TEST_KEY) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext };
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

/** Decrypts the relay's response frames back into status/headers/body. */
async function decodeRelayResponse(response) {
  if (response.headers.get("x-relay-response-encrypted") !== "aes-256-gcm-frame-v1") {
    return { encrypted: false, status: response.status, headers: {}, body: await response.text() };
  }
  const raw = Buffer.from(await response.arrayBuffer());
  let status = response.status;
  let headers = {};
  let terminal = null;
  const chunks = [];
  for (const frame of decodeFrames(raw)) {
    const plaintext = decryptAesGcm(frame.header.iv, frame.header.tag, frame.payload);
    if (frame.header.type === "meta") {
      const meta = JSON.parse(plaintext.toString("utf8"));
      status = meta.status;
      headers = meta.headers;
      continue;
    }
    if (frame.header.type === "end") {
      terminal = JSON.parse(plaintext.toString("utf8"));
      continue;
    }
    assert.equal(frame.header.type, "data");
    chunks.push(plaintext);
  }
  const body = Buffer.concat(chunks);
  return {
    encrypted: true,
    status,
    headers,
    body: body.toString("utf8"),
    raw,
    terminal,
    dataFrames: chunks.length,
    bodySha256: createHash("sha256").update(body).digest("hex")
  };
}

// ---------------------------------------------------------------------------
// v5 client
// ---------------------------------------------------------------------------

function createRelayClient(baseUrl, { secret = SECRET, keyId = "default" } = {}) {
  const authHeaders = secret ? { "x-relay-secret": secret } : {};

  /**
   * Uploads a whole request body, optionally compressed against a base
   * snapshot as a zstd dictionary. `corruptDictionary` compresses against
   * something other than what the relay will use, to prove the relay refuses
   * to forward a body it cannot verify.
   */
  async function send(requestId, bodyBuffer, { base = null, chunkSize = 1 << 20, headers = {}, path, targetUrl } = {}) {
    const payload = base
      ? zstdCompressSync(bodyBuffer, { dictionary: base.dictionary })
      : zstdCompressSync(bodyBuffer);

    const metadata = {
      version: "v5",
      method: "POST",
      path: path ?? "/v1/responses",
      targetUrl: targetUrl ?? TARGET_URL,
      headers: { "content-type": "application/json", ...headers },
      relayTransferEncoding: "zstd",
      bodySize: bodyBuffer.length,
      bodySha256: sha256Hex(bodyBuffer),
      compressedBodySize: payload.length,
      compressedBodySha256: sha256Hex(payload),
      chunkCount: Math.max(1, Math.ceil(payload.length / chunkSize)),
      baseSnapshotId: base ? base.snapshotId : ""
    };
    const envelope = encryptAesGcm(Buffer.from(JSON.stringify(metadata), "utf8"));

    const init = await fetch(`${baseUrl}/relay/v5/request/init`, {
      method: "POST",
      headers: { ...authHeaders, "content-type": "application/json" },
      body: JSON.stringify({
        requestId,
        chunkCount: metadata.chunkCount,
        enc: {
          alg: "aes-256-gcm",
          keyId,
          iv: envelope.iv,
          tag: envelope.tag,
          ciphertext: envelope.ciphertext.toString("base64")
        }
      })
    });
    if (init.status !== 202) {
      return { init, initBody: await init.json(), chunks: [], response: null, decoded: null };
    }

    const chunks = [];
    for (let offset = 0, index = 0; offset < payload.length; offset += chunkSize, index += 1) {
      const encrypted = encryptAesGcm(payload.subarray(offset, offset + chunkSize));
      chunks.push(
        await fetch(`${baseUrl}/relay/v5/request/chunks/${requestId}/${index}`, {
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

    const response = await fetch(`${baseUrl}/relay/v5/request/complete`, {
      method: "POST",
      headers: { ...authHeaders, "content-type": "application/json" },
      body: JSON.stringify({ requestId })
    });
    return {
      init,
      chunks,
      response,
      decoded: await decodeRelayResponse(response),
      wireBytes: payload.length
    };
  }

  async function fetchBase(conversationKey, { keyId = "default", allowCrossConversation = false } = {}) {
    const response = await fetch(`${baseUrl}/relay/v5/snapshot/fetch`, {
      method: "POST",
      headers: { ...authHeaders, "content-type": "application/json" },
      body: JSON.stringify({ conversationKey, keyId, allowCrossConversation })
    });
    if (response.status !== 200) {
      return { status: response.status };
    }
    const raw = Buffer.from(await response.arrayBuffer());
    const bodyChunks = [];
    for (const frame of decodeFrames(raw)) {
      const plaintext = decryptAesGcm(frame.header.iv, frame.header.tag, frame.payload);
      if (frame.header.type === "snapshot") {
        bodyChunks.push(plaintext);
      }
    }
    return {
      status: 200,
      snapshotId: response.headers.get("x-relay-snapshot-id"),
      bodySha256: response.headers.get("x-relay-snapshot-body-sha256"),
      body: Buffer.concat(bodyChunks)
    };
  }

  return { send, fetchBase };
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

function createRelayServer(overrides = {}) {
  return createRelayHandlers(
    {
      relayStorageDir: overrides.relayStorageDir,
      relayRequestTtlMs: 60_000,
      relaySnapshotTtlMs: overrides.relaySnapshotTtlMs ?? 60_000,
      relaySharedSecret: overrides.relaySharedSecret ?? SECRET,
      relayEncryptionKeys: overrides.relayEncryptionKeys ?? { default: TEST_KEY_B64 },
      relayMaxSnapshots: overrides.relayMaxSnapshots ?? 500,
      relayMaxSnapshotBytes: overrides.relayMaxSnapshotBytes ?? 2 * 1024 * 1024 * 1024,
      relayKeepPerConversation: overrides.relayKeepPerConversation ?? 5,
      relayDebugLog: false,
      relayUpstreamMode: overrides.relayUpstreamMode ?? "passthrough",
      cpaBaseUrl: overrides.cpaBaseUrl ?? "",
      cpaApiKey: overrides.cpaApiKey ?? "",
      cpaModelMap: overrides.cpaModelMap ?? {},
      cpaForceModel: overrides.cpaForceModel ?? "",
      cpaDropUnmatched: overrides.cpaDropUnmatched ?? false,
      cpaStripToolNames: overrides.cpaStripToolNames ?? []
    },
    {
      createAbortSignal(_request, response) {
        assert.ok(response, "response is required for abort signal creation");
        return new AbortController().signal;
      }
    }
  );
}

async function withRelay(overrides, run, upstreamFactory) {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const relayHandlers = createRelayServer({ relayStorageDir: storageDir, ...overrides });
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
      : new Response("data: ok\n\n", { status: 200, headers: { "content-type": "text/event-stream" } });
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

/**
 * A Codex-shaped body whose turns are individually incompressible, so a
 * dictionary delta is measured against realistic plain-zstd output rather than
 * against boilerplate that any compressor would collapse anyway.
 */
function turnText(index) {
  let text = "";
  for (let i = 0; i < 40; i += 1) {
    text += createHash("sha256").update(`turn-${index}-${i}`).digest("base64");
  }
  return text;
}

function codexBody(turns, conversation = "conv-1") {
  return Buffer.from(
    JSON.stringify({
      model: "gpt-5.5",
      stream: true,
      prompt_cache_key: conversation,
      instructions: "You are a coding agent. ".repeat(200),
      input: Array.from({ length: turns }, (_, index) => ({
        type: "message",
        id: `msg_${index}`,
        role: index % 2 ? "assistant" : "user",
        content: [{ type: "input_text", text: `turn ${index}: ${turnText(index)}` }]
      }))
    }),
    "utf8"
  );
}

function baseFrom(decoded, bodyBuffer) {
  return { snapshotId: decoded.headers["x-relay-snapshot-id"], dictionary: bodyBuffer };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test("a cold request round-trips without a dictionary", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const body = codexBody(4);
    const { init, decoded } = await client.send("req_cold", body, { headers: { "x-session-id": "s1" } });

    assert.equal(init.status, 202);
    assert.equal(decoded.status, 200);
    assert.equal(decoded.body, "data: ok\n\n");
    assert.equal(captured.length, 1);
    assert.deepEqual(captured[0].body, body, "upstream must receive the exact bytes the client sent");
    assert.equal(captured[0].headers["x-session-id"], "s1");
    assert.ok(decoded.headers["x-relay-snapshot-id"], "a snapshot must be offered for the next turn");
  });
});

test("the wire cost tracks the new content, not the length of the history", async () => {
  await withRelay({}, async ({ captured, client }) => {
    // Two conversations that differ only in how much history precedes the same
    // single new turn. If cost tracked history the second delta would be far
    // larger; the point of the dictionary is that it does not.
    const shortHistory = codexBody(4, "conv-short");
    const longHistory = codexBody(40, "conv-long");
    const shortCold = await client.send("short_1", shortHistory);
    const longCold = await client.send("long_1", longHistory);

    const shortNext = codexBody(5, "conv-short");
    const longNext = codexBody(41, "conv-long");
    const shortDelta = await client.send("short_2", shortNext, {
      base: baseFrom(shortCold.decoded, shortHistory)
    });
    const longDelta = await client.send("long_2", longNext, {
      base: baseFrom(longCold.decoded, longHistory)
    });

    assert.equal(shortDelta.decoded.status, 200);
    assert.equal(longDelta.decoded.status, 200);
    assert.deepEqual(captured[2].body, shortNext);
    assert.deepEqual(captured[3].body, longNext);

    // The long conversation's body is many times bigger...
    assert.ok(
      longNext.length > shortNext.length * 4,
      `histories should differ substantially: ${longNext.length} vs ${shortNext.length}`
    );
    // ...but its delta is not, because both added exactly one turn.
    assert.ok(
      longDelta.wireBytes < shortDelta.wireBytes * 1.5,
      `delta must not scale with history: ${longDelta.wireBytes} vs ${shortDelta.wireBytes}`
    );
    // And a delta must beat sending the same turn cold.
    assert.ok(
      longDelta.wireBytes * 5 < longCold.wireBytes,
      `delta should be far cheaper than cold: ${longDelta.wireBytes} vs ${longCold.wireBytes}`
    );
  });
});

test("a shorter history still rebuilds, which is what a rewind produces", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const long = codexBody(10);
    const cold = await client.send("req_long", long);

    const rewound = codexBody(4);
    const { decoded } = await client.send("req_rewound", rewound, {
      base: baseFrom(cold.decoded, long)
    });

    assert.equal(decoded.status, 200);
    assert.deepEqual(captured[1].body, rewound);
  });
});

test("a stale base is rejected at init, before any chunk is uploaded", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const body = codexBody(4);
    const { init, initBody, chunks } = await client.send("req_stale", body, {
      base: { snapshotId: "snap_does_not_exist", dictionary: body }
    });

    assert.equal(init.status, 409);
    assert.equal(initBody.error.code, "base_snapshot_unavailable");
    assert.equal(initBody.error.baseSnapshotId, "snap_does_not_exist");
    assert.equal(chunks.length, 0, "no chunk should be uploaded once the base is known to be gone");
    assert.equal(captured.length, 0);
  });
});

test("a body compressed against the wrong base never reaches upstream", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const first = codexBody(4);
    const cold = await client.send("req_a", first);

    // Claim the real snapshot but compress against something else: the relay
    // decompresses into different bytes, and the hash check has to catch it.
    const second = codexBody(6);
    const { response } = await client.send("req_b", second, {
      base: { snapshotId: cold.decoded.headers["x-relay-snapshot-id"], dictionary: codexBody(9) }
    });

    assert.ok([400, 409].includes(response.status), `expected a rejection, got ${response.status}`);
    assert.equal(captured.length, 1, "only the first request may have reached upstream");
  });
});

test("responses are always encrypted frames, never plaintext", async () => {
  await withRelay(
    {},
    async ({ client }) => {
      const { response, decoded } = await client.send("req_enc", codexBody(2));

      assert.equal(response.headers.get("x-relay-response-encrypted"), "aes-256-gcm-frame-v1");
      assert.equal(response.headers.get("content-type"), "application/octet-stream");
      // status and content type ride as clear headers so the client can stream
      assert.equal(response.headers.get("x-relay-upstream-status"), "200");
      assert.equal(response.headers.get("x-relay-upstream-content-type"), "text/event-stream");
      assert.ok(
        !decoded.raw.includes(Buffer.from("top-secret-answer", "utf8")),
        "the response body must not appear in plaintext on the wire"
      );
      assert.equal(decoded.body, "data: top-secret-answer\n\n");
    },
    () =>
      new Response("data: top-secret-answer\n\n", {
        status: 200,
        headers: { "content-type": "text/event-stream" }
      })
  );
});

test("the upstream content-encoding fetch already decoded is not forwarded", async () => {
  await withRelay(
    {},
    async ({ client }) => {
      const { decoded } = await client.send("req_ce", codexBody(2));
      assert.equal(decoded.headers["content-encoding"], undefined);
      assert.equal(decoded.headers["content-length"], undefined);
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

test("concurrent conversations keep their own base", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const aFirst = codexBody(4, "conv-a");
    const bFirst = codexBody(4, "conv-b");
    const a1 = await client.send("a1", aFirst, {});
    const b1 = await client.send("b1", bFirst, {});

    // Interleaved follow-ups, each against its own conversation's snapshot.
    const aSecond = codexBody(6, "conv-a");
    const bSecond = codexBody(6, "conv-b");
    const a2 = await client.send("a2", aSecond, { base: baseFrom(a1.decoded, aFirst) });
    const b2 = await client.send("b2", bSecond, { base: baseFrom(b1.decoded, bFirst) });

    assert.equal(a2.decoded.status, 200);
    assert.equal(b2.decoded.status, 200);
    assert.deepEqual(captured[2].body, aSecond);
    assert.deepEqual(captured[3].body, bSecond);
  });
});

test("a conversation keeps spares so an in-flight client is not stranded", async () => {
  await withRelay({ relayKeepPerConversation: 5 }, async ({ client, storageDir }) => {
    const first = codexBody(4, "conv-x");
    const one = await client.send("s1", first);

    // Four more turns, all while the client still believes in s1's snapshot -
    // which is what happens when it has not finished streaming the responses.
    let previous = one;
    let previousBody = first;
    for (const [index, turns] of [6, 8, 10, 12].entries()) {
      const body = codexBody(turns, "conv-x");
      previous = await client.send(`s${index + 2}`, body, {
        base: baseFrom(previous.decoded, previousBody)
      });
      previousBody = body;
      assert.equal(previous.decoded.status, 200);
    }

    // The original base must still work: five deep is the whole point.
    const late = codexBody(14, "conv-x");
    const { decoded } = await client.send("s_late", late, { base: baseFrom(one.decoded, first) });
    assert.equal(decoded.status, 200, "a base five turns old must still be usable");

    const kept = await readdir(join(storageDir, "snapshots"));
    assert.ok(kept.length <= 6, `retention should stay bounded, found ${kept.length}`);
  });
});

test("snapshots beyond the per-conversation depth are dropped", async () => {
  await withRelay({ relayKeepPerConversation: 2 }, async ({ client, storageDir }) => {
    const first = codexBody(4, "conv-depth");
    const one = await client.send("d1", first);
    let previous = one;
    let previousBody = first;
    for (const [index, turns] of [6, 8, 10].entries()) {
      const body = codexBody(turns, "conv-depth");
      previous = await client.send(`d${index + 2}`, body, {
        base: baseFrom(previous.decoded, previousBody)
      });
      previousBody = body;
    }

    const kept = await readdir(join(storageDir, "snapshots"));
    assert.ok(kept.length <= 3, `depth 2 should keep at most 3, found ${kept.length}`);

    // The oldest base is gone, and the client is told so rather than guessing.
    const { init, initBody } = await client.send("d_stale", codexBody(12, "conv-depth"), {
      base: baseFrom(one.decoded, first)
    });
    assert.equal(init.status, 409);
    assert.equal(initBody.error.code, "base_snapshot_unavailable");
  });
});

test("the byte cap evicts even when the count is fine", async () => {
  // One snapshot's worth of headroom: everything older has to go.
  await withRelay({ relayMaxSnapshotBytes: 4096, relayMaxSnapshots: 500 }, async ({ client, storageDir }) => {
    for (let index = 0; index < 4; index += 1) {
      const { decoded } = await client.send(`b${index}`, codexBody(6, `conv-b${index}`));
      assert.equal(decoded.status, 200);
    }
    const kept = await readdir(join(storageDir, "snapshots"));
    assert.ok(kept.length < 4, `byte cap should have evicted something, found ${kept.length}`);
    assert.ok(kept.length >= 1, "the newest snapshot must always survive");
  });
});

test("expired snapshots are purged on the next write", async () => {
  await withRelay({ relaySnapshotTtlMs: 1 }, async ({ client, storageDir }) => {
    await client.send("e1", codexBody(4, "conv-e1"));
    await new Promise((resolve) => setTimeout(resolve, 20));
    await client.send("e2", codexBody(4, "conv-e2"));

    const kept = await readdir(join(storageDir, "snapshots"));
    assert.equal(kept.length, 1, "only the snapshot just written should survive its TTL");
  });
});


test("snapshots are encrypted at rest, not plaintext on the volume", async () => {
  const secret = "a-very-private-line-from-the-conversation";
  await withRelay({}, async ({ client, storageDir }) => {
    const body = Buffer.from(
      JSON.stringify({ model: "gpt-5.5", prompt_cache_key: "c", input: [{ text: secret }] }),
      "utf8"
    );
    const { decoded } = await client.send("req_at_rest", body);
    assert.equal(decoded.status, 200);

    const offenders = [];
    async function walk(dir) {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(full);
          continue;
        }
        try {
          if ((await readFile(full, "utf8")).includes(secret)) {
            offenders.push(full);
          }
        } catch {
          // binary or removed
        }
      }
    }
    await walk(storageDir);
    assert.deepEqual(offenders, [], `plaintext found on disk: ${offenders.join(", ")}`);

    const [snapshotId] = await readdir(join(storageDir, "snapshots"));
    const envelope = JSON.parse(
      await readFile(join(storageDir, "snapshots", snapshotId, "body.bin"), "utf8")
    );
    assert.equal(envelope.v, 1);
    assert.equal(envelope.alg, "aes-256-gcm");
    assert.ok(envelope.ciphertext);
  });
});

test("an encrypted snapshot still works as a dictionary", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const first = codexBody(4);
    const cold = await client.send("sealed_1", first);
    const second = codexBody(6);
    const { decoded } = await client.send("sealed_2", second, { base: baseFrom(cold.decoded, first) });

    assert.equal(decoded.status, 200);
    assert.deepEqual(captured[1].body, second);
  });
});

test("relay rejects a chunk whose checksum does not match", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/relay/v5/request/chunks/req_bad/0`, {
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
    const response = await fetch(`${baseUrl}/relay/v5/request/chunks/req_x/0`, {
      method: "PUT",
      headers: { "x-relay-secret": SECRET },
      body: Buffer.from("plaintext")
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error.message, /missing chunk encryption headers/);
  });
});

test("relay rejects an unencrypted init payload", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/relay/v5/request/init`, {
      method: "POST",
      headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
      body: JSON.stringify({ requestId: "req_plain", method: "POST", path: "/x", targetUrl: TARGET_URL })
    });
    assert.equal(response.status, 400);
    assert.match((await response.json()).error.message, /encrypted envelope is required/);
  });
});

test("relay rejects an unknown encryption key id", async () => {
  await withRelay({ relayEncryptionKeys: { other: TEST_KEY_B64 } }, async ({ baseUrl }) => {
    const envelope = encryptAesGcm(Buffer.from("{}", "utf8"));
    const response = await fetch(`${baseUrl}/relay/v5/request/init`, {
      method: "POST",
      headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
      body: JSON.stringify({
        requestId: "req_key",
        chunkCount: 1,
        enc: {
          alg: "aes-256-gcm",
          keyId: "default",
          iv: envelope.iv,
          tag: envelope.tag,
          ciphertext: envelope.ciphertext.toString("base64")
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
      ["/relay/v5/request/init", "POST"],
      ["/relay/v5/request/chunks/req/0", "PUT"],
      ["/relay/v5/request/complete", "POST"]
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

test("legacy v1/v2/v4 routes are gone", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    for (const path of [
      "/relay/v1/chunked/init",
      "/relay/v2/chunked/complete",
      "/relay/v4/full/init",
      "/relay/v4/delta/complete",
      "/relay/v4/refs/init"
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

test("a body split across many chunks reassembles", async () => {
  await withRelay({}, async ({ captured, client }) => {
    // incompressible, so it cannot collapse back into a single chunk
    const body = Buffer.from(
      JSON.stringify({ model: "gpt-5.5", blob: randomBytes(120_000).toString("base64") }),
      "utf8"
    );
    const { chunks, decoded } = await client.send("req_big", body, { chunkSize: 20 * 1024 });

    assert.ok(chunks.length > 1, "expected the payload to be split");
    for (const chunk of chunks) {
      assert.equal(chunk.status, 202);
    }
    assert.equal(decoded.status, 200);
    assert.deepEqual(captured[0].body, body);
  });
});

test("an upstream failure surfaces as 502 rather than hanging", async () => {
  await withRelay(
    {},
    async ({ client }) => {
      const { response, decoded } = await client.send("req_502", codexBody(2));
      assert.equal(response.status, 502);
      assert.match(JSON.parse(decoded.body).error.message, /upstream exploded/);
    },
    () => {
      throw new Error("upstream exploded");
    }
  );
});

test("cpa mode retargets the rebuilt request at CPA with its own api key", async () => {
  await withRelay(
    {
      relayUpstreamMode: "cpa",
      cpaBaseUrl: "http://cli-proxy-api:8317",
      cpaApiKey: "cpa-key",
      cpaStripToolNames: ["image_gen"]
    },
    async ({ captured, client }) => {
      const body = Buffer.from(
        JSON.stringify({
          model: "gpt-5.5",
          prompt_cache_key: "conv-cpa",
          tools: [{ type: "function", name: "exec_command" }, { type: "namespace", name: "image_gen" }]
        }),
        "utf8"
      );
      const { decoded } = await client.send("req_cpa", body, {
        headers: { authorization: "Bearer stale", "x-session-id": "sess_cpa" }
      });

      assert.equal(decoded.status, 200);
      assert.equal(captured[0].url, "http://cli-proxy-api:8317/v1/responses");
      assert.equal(captured[0].headers.authorization, "Bearer cpa-key");
      assert.equal(captured[0].headers["x-session-id"], "sess_cpa");
      assert.deepEqual(JSON.parse(captured[0].body.toString("utf8")).tools, [
        { type: "function", name: "exec_command" }
      ]);
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
      const { decoded } = await client.send("req_metrics", Buffer.from('{"metrics":[]}', "utf8"), {
        path: "/otlp/v1/metrics",
        targetUrl: "https://ab.chatgpt.com/otlp/v1/metrics"
      });

      assert.equal(decoded.status, 204);
      assert.equal(captured.length, 0, "telemetry must not reach any upstream");
    }
  );
});

test("a terminal frame makes truncation detectable", async () => {
  await withRelay(
    {},
    async ({ client }) => {
      const { decoded } = await client.send("req_terminal", codexBody(2));

      assert.ok(decoded.terminal, "every response must carry a terminal frame");
      assert.equal(decoded.terminal.dataFrames, decoded.dataFrames);
      assert.equal(decoded.terminal.bodySha256, decoded.bodySha256);

      // A client that stopped one frame early would compute a different count
      // and digest, which is exactly what lets it refuse a partial answer.
      assert.notEqual(
        decoded.terminal.bodySha256,
        createHash("sha256").update("data: partial").digest("hex")
      );
    },
    () =>
      new Response("data: one\n\ndata: two\n\ndata: three\n\n", {
        status: 200,
        headers: { "content-type": "text/event-stream" }
      })
  );
});

test("a client can fetch back a base the relay still holds", async () => {
  await withRelay({}, async ({ captured, client }) => {
    const first = codexBody(6, "conv-restart");
    const cold = await client.send("r1", first);
    const storedId = cold.decoded.headers["x-relay-snapshot-id"];

    // Simulate a client restart: it kept nothing. It asks the relay for a base.
    const fetched = await client.fetchBase("conv-restart");
    assert.equal(fetched.status, 200);
    assert.equal(fetched.snapshotId, storedId);
    assert.deepEqual(fetched.body, first, "the fetched base must be the exact bytes both sides compress against");
    assert.equal(fetched.bodySha256, createHash("sha256").update(first).digest("hex"));

    // And it works as a dictionary: the next turn is incremental again.
    const second = codexBody(8, "conv-restart");
    const delta = await client.send("r2", second, {
      base: { snapshotId: fetched.snapshotId, dictionary: fetched.body }
    });
    assert.equal(delta.decoded.status, 200);
    assert.deepEqual(captured[1].body, second);

    // Compare against sending the same turn with no base at all: the fetched
    // base must beat it clearly, which is the whole point of fetching it.
    const noBase = await client.send("r2_nobase", second);
    assert.ok(
      delta.wireBytes * 2 < noBase.wireBytes,
      `fetched base should beat no base: ${delta.wireBytes} vs ${noBase.wireBytes}`
    );
  });
});

test("fetching a base the relay never had returns 404", async () => {
  await withRelay({}, async ({ client }) => {
    const fetched = await client.fetchBase("conv-never-seen");
    assert.equal(fetched.status, 404);
  });
});

test("the snapshot fetch body is ciphertext, and needs the secret", async () => {
  const secret = "a-private-line-in-the-only-request";
  await withRelay({}, async ({ baseUrl, client }) => {
    const body = Buffer.from(
      JSON.stringify({ model: "gpt-5.5", prompt_cache_key: "conv-sec", input: [{ text: secret }] }),
      "utf8"
    );
    await client.send("sec1", body);

    // No secret -> refused.
    const noAuth = await fetch(`${baseUrl}/relay/v5/snapshot/fetch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ conversationKey: "conv-sec", keyId: "default" })
    });
    assert.equal(noAuth.status, 401);

    // With secret -> served, but the plaintext never appears on the wire.
    const fetched = await client.fetchBase("conv-sec");
    assert.equal(fetched.status, 200);
    const raw = fetched.body; // this is already-decrypted; check the wire form instead
    const wire = await fetch(`${baseUrl}/relay/v5/snapshot/fetch`, {
      method: "POST",
      headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
      body: JSON.stringify({ conversationKey: "conv-sec", keyId: "default" })
    });
    const wireBytes = Buffer.from(await wire.arrayBuffer());
    assert.ok(!wireBytes.includes(Buffer.from(secret, "utf8")), "conversation content must be encrypted on the wire");
    assert.ok(raw.includes(Buffer.from(secret, "utf8")), "the decrypted base should contain the original content");
  });
});

test("cross-conversation fallback warms a new conversation after a restart", async () => {
  await withRelay({}, async ({ client }) => {
    const prior = codexBody(6, "conv-prior");
    await client.send("p1", prior);

    // A different conversation the relay has never seen. By key: 404.
    const byKey = await client.fetchBase("conv-brand-new");
    assert.equal(byKey.status, 404);

    // With the fallback it hands back the prior conversation's base instead.
    const cross = await client.fetchBase("conv-brand-new", { allowCrossConversation: true });
    assert.equal(cross.status, 200);
    assert.deepEqual(cross.body, prior);
  });
});

// ---------------------------------------------------------------------------
// SWG probes
// ---------------------------------------------------------------------------

test("the drip probe replays the streamed response shape and needs the secret", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    const denied = await fetch(`${baseUrl}/relay/probe/drip?d=0.1`, { method: "POST" });
    assert.equal(denied.status, 401);

    const response = await fetch(`${baseUrl}/relay/probe/drip?d=0.3&rate=4000&tick=50`, {
      method: "POST",
      headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
      body: JSON.stringify({ requestId: "probe" })
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "application/octet-stream");
    assert.equal(response.headers.get("x-relay-response-encrypted"), "aes-256-gcm-frame-v1");
    assert.equal(response.headers.get("x-relay-upstream-status"), "200");
    assert.ok(response.headers.get("x-relay-snapshot-id").startsWith("snap_"));
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("content-length"), null);

    const raw = Buffer.from(await response.arrayBuffer());
    const frames = decodeFrames(raw);
    assert.equal(frames[0].header.type, "meta");
    assert.ok(frames.length >= 4, `expected several data frames, got ${frames.length}`);
    assert.ok(frames.slice(1).every((frame) => frame.header.type === "data"));
    // real key configured, so the payload decrypts like a real response would
    const plaintext = decryptAesGcm(frames[1].header.iv, frames[1].header.tag, frames[1].payload);
    assert.ok(plaintext.toString("utf8").startsWith("data: "));
  });
});

test("the drip probe can drop the relay headers and switch body and content type", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    const response = await fetch(
      `${baseUrl}/relay/probe/drip?d=0.2&rate=2000&tick=50&hdr=0&body=ascii&ct=text/event-stream`,
      { headers: { "x-relay-secret": SECRET } }
    );
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "text/event-stream");
    assert.equal(response.headers.get("x-relay-response-encrypted"), null);
    assert.equal(response.headers.get("x-relay-upstream-status"), null);
    const text = await response.text();
    assert.ok(text.startsWith("data: "));
    assert.ok(text.length >= 200);

    const random = await fetch(`${baseUrl}/relay/probe/drip?d=0.2&rate=2000&tick=50&body=random`, {
      headers: { "x-relay-secret": SECRET }
    });
    const bytes = Buffer.from(await random.arrayBuffer());
    assert.ok(bytes.length >= 200);
  });
});

test("the drip probe also answers on the real complete path", async () => {
  await withRelay({}, async ({ baseUrl, captured }) => {
    const response = await fetch(`${baseUrl}/relay/v5/request/complete?probe=drip&d=0.2&rate=1000&tick=50`, {
      method: "POST",
      headers: { "x-relay-secret": SECRET, "content-type": "application/json" },
      body: JSON.stringify({ requestId: "probe" })
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-relay-response-encrypted"), "aes-256-gcm-frame-v1");
    await response.arrayBuffer();
    assert.equal(captured.length, 0, "a probe must never reach upstream");
  });
});

test("the delay probe stays silent, then answers", async () => {
  await withRelay({}, async ({ baseUrl }) => {
    const startedAt = Date.now();
    const response = await fetch(`${baseUrl}/relay/probe/delay?ms=150`, {
      headers: { "x-relay-secret": SECRET }
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.ok, true);
    assert.ok(Date.now() - startedAt >= 140);
  });
});
