#!/usr/bin/env node
// End-to-end smoke test against a running relay, without mitmproxy in the way.
// Speaks the v5 wire protocol: the payload is always the whole request body,
// zstd-compressed (optionally against a snapshot both sides hold), AES-256-GCM
// chunked, with an encrypted response.
//
//   node scripts/smoke-relay.mjs --base-url https://codex.liahuas.top \
//     --secret <RELAY_SHARED_SECRET> --key <base64 32-byte key> \
//     --model gpt-5.5 --history-kb 500
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { zstdCompressSync } from "node:zlib";

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const BASE_URL = arg("base-url", "http://127.0.0.1:8788").replace(/\/+$/, "");
const SECRET = arg("secret", "");
const KEY_B64 = arg("key", "");
const KEY_ID = arg("key-id", "default");
const MODEL = arg("model", "gpt-5.5");
const TARGET_URL = arg("target-url", "https://codex.liahuas.top/v1/responses");
const CHUNK_SIZE = Number(arg("chunk-size", "20480"));
const HISTORY_KB = Number(arg("history-kb", "0"));

if (!KEY_B64) {
  console.error("--key is required: v5 has no unencrypted mode");
  process.exit(2);
}
const KEY = Buffer.from(KEY_B64, "base64");
if (KEY.length !== 32) {
  console.error("--key must be a base64-encoded 32-byte AES key");
  process.exit(2);
}

const sha256Hex = (buffer) => createHash("sha256").update(buffer).digest("hex");

function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext };
}

function decrypt(ivB64, tagB64, ciphertext) {
  const decipher = createDecipheriv("aes-256-gcm", KEY, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
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

const authHeaders = SECRET ? { "x-relay-secret": SECRET } : {};
const jsonHeaders = () => ({ ...authHeaders, "content-type": "application/json" });

async function expect(response, status, label) {
  if (response.status !== status) {
    throw new Error(`${label}: expected ${status}, got ${response.status} ${await response.text()}`);
  }
  return response;
}

async function readRelayResponse(response) {
  if (response.headers.get("x-relay-response-encrypted") !== "aes-256-gcm-frame-v1") {
    return { encrypted: false, status: response.status, headers: {}, body: await response.text() };
  }
  const raw = Buffer.from(await response.arrayBuffer());
  let status = response.status;
  let headers = {};
  const chunks = [];
  for (const frame of decodeFrames(raw)) {
    const plaintext = decrypt(frame.header.iv, frame.header.tag, frame.payload);
    if (frame.header.type === "meta") {
      const meta = JSON.parse(plaintext.toString("utf8"));
      status = meta.status;
      headers = meta.headers;
      continue;
    }
    chunks.push(plaintext);
  }
  return { encrypted: true, status, headers, body: Buffer.concat(chunks).toString("utf8") };
}

/** One request: compress (optionally against a base), encrypt, chunk, complete. */
async function send(requestId, bodyBuffer, base) {
  const payload = base ? zstdCompressSync(bodyBuffer, { dictionary: base.body }) : zstdCompressSync(bodyBuffer);
  const chunkCount = Math.max(1, Math.ceil(payload.length / CHUNK_SIZE));
  const envelope = encrypt(
    Buffer.from(
      JSON.stringify({
        version: "v5",
        method: "POST",
        path: "/v1/responses",
        targetUrl: TARGET_URL,
        headers: { "content-type": "application/json", "x-session-id": "smoke" },
        relayTransferEncoding: "zstd",
        bodySize: bodyBuffer.length,
        bodySha256: sha256Hex(bodyBuffer),
        compressedBodySize: payload.length,
        compressedBodySha256: sha256Hex(payload),
        chunkCount,
        baseSnapshotId: base ? base.snapshotId : ""
      }),
      "utf8"
    )
  );

  await expect(
    await fetch(`${BASE_URL}/relay/v5/request/init`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({
        requestId,
        chunkCount,
        enc: {
          alg: "aes-256-gcm",
          keyId: KEY_ID,
          iv: envelope.iv,
          tag: envelope.tag,
          ciphertext: envelope.ciphertext.toString("base64")
        }
      })
    }),
    202,
    "init"
  );

  let maxChunk = 0;
  for (let offset = 0, index = 0; offset < payload.length; offset += CHUNK_SIZE, index += 1) {
    const encrypted = encrypt(payload.subarray(offset, offset + CHUNK_SIZE));
    maxChunk = Math.max(maxChunk, encrypted.ciphertext.length);
    await expect(
      await fetch(`${BASE_URL}/relay/v5/request/chunks/${requestId}/${index}`, {
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
      }),
      202,
      `chunk ${index}`
    );
  }

  const parsed = await readRelayResponse(
    await fetch(`${BASE_URL}/relay/v5/request/complete`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ requestId })
    })
  );
  return { parsed, wireBytes: payload.length, chunkCount, maxChunk };
}

function userItem(text) {
  return { type: "message", role: "user", content: [{ type: "input_text", text }] };
}

function historyItem(kilobytes) {
  const line = "// prior conversation context that must not be re-uploaded every turn\n";
  return userItem(line.repeat(Math.ceil((kilobytes * 1024) / line.length)));
}

function body(conversation, inputItems) {
  return Buffer.from(
    JSON.stringify({
      model: MODEL,
      stream: true,
      store: false,
      prompt_cache_key: conversation,
      instructions: "You are a terse assistant. Answer in one short word.",
      input: inputItems
    }),
    "utf8"
  );
}

function outputText(sse) {
  const texts = [];
  for (const line of sse.split("\n")) {
    if (!line.startsWith("data:")) continue;
    try {
      const event = JSON.parse(line.slice(5).trim());
      if (event.type === "response.output_text.delta" && typeof event.delta === "string") {
        texts.push(event.delta);
      }
    } catch {
      // non-JSON SSE line
    }
  }
  return texts.join("");
}

async function main() {
  const rows = [];
  const suffix = randomBytes(6).toString("hex");
  const conversation = `smoke-${suffix}`;

  const history = HISTORY_KB > 0 ? [historyItem(HISTORY_KB)] : [];
  const turn1Input = [...history, userItem("Reply with exactly: ALPHA")];
  const turn1 = body(conversation, turn1Input);
  const cold = await send(`smoke_1_${suffix}`, turn1, null);
  rows.push({
    turn: "1 cold",
    status: cold.parsed.status,
    encrypted: cold.parsed.encrypted,
    text: outputText(cold.parsed.body).trim(),
    "body B": turn1.length,
    "wire B": cold.wireBytes,
    chunks: cold.chunkCount
  });

  const snapshotId = cold.parsed.headers["x-relay-snapshot-id"];
  if (!snapshotId) {
    throw new Error("relay returned no snapshot id; an incremental turn is impossible");
  }

  const turn2Input = [
    ...turn1Input,
    { type: "message", role: "assistant", content: [{ type: "output_text", text: "ALPHA" }] },
    userItem("Reply with exactly: BRAVO")
  ];
  const turn2 = body(conversation, turn2Input);
  const delta = await send(`smoke_2_${suffix}`, turn2, { snapshotId, body: turn1 });
  rows.push({
    turn: "2 delta",
    status: delta.parsed.status,
    encrypted: delta.parsed.encrypted,
    text: outputText(delta.parsed.body).trim(),
    "body B": turn2.length,
    "wire B": delta.wireBytes,
    chunks: delta.chunkCount
  });

  console.table(rows);
  console.log(
    `\nturn 2 body was ${turn2.length.toLocaleString()} B; ${delta.wireBytes.toLocaleString()} B went over ` +
      `the wire (${(turn2.length / delta.wireBytes).toFixed(0)}x smaller)`
  );
  console.log(
    `largest single request body: ${Math.max(cold.maxChunk, delta.maxChunk).toLocaleString()} B ` +
      `(chunk size ${CHUNK_SIZE.toLocaleString()} B)`
  );

  const failures = rows.filter((row) => row.status !== 200 || !row.encrypted);
  if (failures.length) {
    console.error("\nFAILED:", failures);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
