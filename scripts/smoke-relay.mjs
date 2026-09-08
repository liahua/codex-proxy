#!/usr/bin/env node
// End-to-end smoke test against a running relay, without mitmproxy in the way.
// Speaks the v4 wire protocol exactly as the mitm addon does:
//   full   whole body, gzip + AES-256-GCM chunks, encrypted response frames
//   delta  second turn ships only the new input tail
//
//   node scripts/smoke-relay.mjs --base-url https://codex.liahuas.top \
//     --secret <RELAY_SHARED_SECRET> --key <base64 32-byte key> \
//     --model gpt-5.5 --history-kb 200
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const BASE_URL = arg("base-url", "http://127.0.0.1:8788").replace(/\/+$/, "");
const SECRET = arg("secret", "");
const KEY_B64 = arg("key", "");
const KEY_ID = arg("key-id", "default");
const MODEL = arg("model", "gpt-5.5");
const TARGET_URL = arg("target-url", "https://chatgpt.com/backend-api/codex/responses");
const CHUNK_SIZE = Number(arg("chunk-size", "20480"));
// Pads the first turn so the delta turn has a realistic history to skip re-sending.
const HISTORY_KB = Number(arg("history-kb", "0"));

if (!KEY_B64) {
  console.error("--key is required: v4 has no unencrypted mode");
  process.exit(2);
}
const KEY = Buffer.from(KEY_B64, "base64");
if (KEY.length !== 32) {
  console.error("--key must be a base64-encoded 32-byte AES key");
  process.exit(2);
}

function sha256Hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
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

function jsonHeaders() {
  return { ...authHeaders, "content-type": "application/json" };
}

function forwardHeaders() {
  return { "content-type": "application/json", "x-session-id": "smoke-session" };
}

async function expect(response, status, label) {
  if (response.status !== status) {
    throw new Error(`${label}: expected ${status}, got ${response.status} ${await response.text()}`);
  }
  return response;
}

/** Reads the relay's encrypted response frames back into status/headers/body. */
async function readRelayResponse(response) {
  if (response.headers.get("x-relay-response-encrypted") !== "aes-256-gcm-frame-v1") {
    return {
      encrypted: false,
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body: await response.text()
    };
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
  return {
    encrypted: true,
    status,
    headers,
    body: Buffer.concat(chunks).toString("utf8"),
    wireBytes: raw.length
  };
}

/** Uploads a gzip + AES-GCM chunked payload to one of the v4 init routes. */
async function uploadEncrypted(kind, requestId, metadata, payloadBuffer) {
  const compressed = gzipSync(payloadBuffer);
  const chunkCount = Math.max(1, Math.ceil(compressed.length / CHUNK_SIZE));
  const envelope = encrypt(
    Buffer.from(
      JSON.stringify({
        ...metadata,
        relayTransferEncoding: "gzip",
        bodySize: payloadBuffer.length,
        bodySha256: sha256Hex(payloadBuffer),
        compressedBodySize: compressed.length,
        compressedBodySha256: sha256Hex(compressed),
        chunkCount
      }),
      "utf8"
    )
  );

  await expect(
    await fetch(`${BASE_URL}/relay/v4/${kind}/init`, {
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
    `v4 ${kind} init`
  );

  let maxChunkBytes = 0;
  for (let offset = 0, index = 0; offset < compressed.length; offset += CHUNK_SIZE, index += 1) {
    const encrypted = encrypt(compressed.subarray(offset, offset + CHUNK_SIZE));
    maxChunkBytes = Math.max(maxChunkBytes, encrypted.ciphertext.length);
    await expect(
      await fetch(`${BASE_URL}/relay/v4/${kind}/chunks/${requestId}/${index}`, {
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
      `v4 ${kind} chunk ${index}`
    );
  }

  return {
    payloadBytes: payloadBuffer.length,
    compressedBytes: compressed.length,
    chunkCount,
    maxChunkBytes
  };
}

async function complete(kind, requestId) {
  const response = await fetch(`${BASE_URL}/relay/v4/${kind}/complete`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ requestId })
  });
  return readRelayResponse(response);
}

function body(inputItems) {
  return {
    model: MODEL,
    stream: true,
    store: false,
    instructions: "You are a terse assistant. Answer in one short word.",
    input: inputItems
  };
}

function userItem(text) {
  return { type: "message", role: "user", content: [{ type: "input_text", text }] };
}

/** A bulky prior-context item, standing in for a real conversation history. */
function historyItem(kilobytes) {
  const line = "// prior conversation context that must not be re-uploaded every turn\n";
  return userItem(line.repeat(Math.ceil((kilobytes * 1024) / line.length)));
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
  const results = [];
  const suffix = randomBytes(6).toString("hex");

  // --- turn 1: full encrypted upload -----------------------------------------
  const firstInput = [
    ...(HISTORY_KB > 0 ? [historyItem(HISTORY_KB)] : []),
    userItem("Reply with exactly: ALPHA")
  ];
  const firstBody = body(firstInput);
  const fullId = `smoke_full_${suffix}`;
  const fullSizes = await uploadEncrypted(
    "full",
    fullId,
    {
      version: "v4-full",
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: TARGET_URL,
      headers: forwardHeaders()
    },
    Buffer.from(JSON.stringify(firstBody), "utf8")
  );
  const first = await complete("full", fullId);
  results.push({
    turn: "1 full",
    status: first.status,
    encrypted: first.encrypted,
    text: outputText(first.body).trim(),
    "upload B": fullSizes.compressedBytes,
    chunks: fullSizes.chunkCount,
    "max chunk B": fullSizes.maxChunkBytes
  });

  const snapshotId = first.headers["x-relay-snapshot-id"];
  const snapshotSha = first.headers["x-relay-snapshot-body-sha256"];
  if (!snapshotId) {
    throw new Error("relay returned no request snapshot id; a delta turn is impossible");
  }

  // --- turn 2: delta ---------------------------------------------------------
  const secondInput = [
    ...firstInput,
    { type: "message", role: "assistant", content: [{ type: "output_text", text: "ALPHA" }] },
    userItem("Reply with exactly: BRAVO")
  ];
  const secondBody = body(secondInput);
  const deltaId = `smoke_delta_${suffix}`;
  const deltaSizes = await uploadEncrypted(
    "delta",
    deltaId,
    { version: "v4-delta-chunked" },
    Buffer.from(
      JSON.stringify({
        requestId: deltaId,
        method: "POST",
        path: "/backend-api/codex/responses",
        targetUrl: TARGET_URL,
        headers: forwardHeaders(),
        baseSnapshotId: snapshotId,
        baseBodySha256: snapshotSha,
        patchType: "responses-input-tail-v1",
        baseInputItemCount: firstInput.length,
        appendInputItems: secondInput.slice(firstInput.length),
        bodyFields: Object.fromEntries(Object.entries(secondBody).filter(([key]) => key !== "input")),
        canonicalBodySha256: canonicalJsonHash(secondBody)
      }),
      "utf8"
    )
  );
  const second = await complete("delta", deltaId);
  results.push({
    turn: "2 delta",
    status: second.status,
    encrypted: second.encrypted,
    text: outputText(second.body).trim(),
    "upload B": deltaSizes.compressedBytes,
    chunks: deltaSizes.chunkCount,
    "max chunk B": deltaSizes.maxChunkBytes
  });

  console.table(results);

  const fullTurn2Bytes = Buffer.byteLength(JSON.stringify(secondBody), "utf8");
  console.log(
    `\ndelta: turn 2 was ${fullTurn2Bytes} B of JSON, but only ` +
      `${deltaSizes.compressedBytes} B went over the wire ` +
      `(${(100 - (deltaSizes.compressedBytes / fullTurn2Bytes) * 100).toFixed(1)}% smaller)`
  );
  console.log(
    `largest single request body: ${Math.max(fullSizes.maxChunkBytes, deltaSizes.maxChunkBytes)} B ` +
      `(chunk size ${CHUNK_SIZE} B)`
  );

  const failures = results.filter((row) => row.status !== 200 || !row.encrypted);
  if (failures.length) {
    console.error("\nFAILED:", failures);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
