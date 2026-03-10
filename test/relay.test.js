import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createRelayHandlers } from "../src/relay.js";

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

test("relay handlers reassemble chunks and forward upstream response", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const captured = {
    requestHeaders: null,
    requestBody: null,
    credentials: null
  };

  const relayHandlers = createRelayHandlers(
    {
      relayStorageDir: storageDir,
      relayRequestTtlMs: 60_000,
      relaySharedSecret: "secret",
      codexDefaultModel: "gpt-5.4",
      codexAllowedModels: ["gpt-5.4"],
      codexBaseUrl: "https://chatgpt.com/backend-api",
      codexOriginator: "codex-proxy"
    },
    {
      tokenManager: {
        async getCredentials(requestHeaders) {
          captured.requestHeaders = requestHeaders;
          const credentials = { accessToken: "token", accountId: "acc_test" };
          captured.credentials = credentials;
          return credentials;
        }
      },
      buildUpstreamRequest(config, requestBody, credentials, requestHeaders) {
        captured.requestBody = requestBody;
        return {
          url: "https://example.invalid/codex/responses",
          headers: new Headers({
            Authorization: `Bearer ${credentials.accessToken}`,
            "chatgpt-account-id": credentials.accountId,
            "x-test-header": requestHeaders["x-session-id"] || ""
          }),
          body: requestBody
        };
      },
      async sendToCodex(_fetchImpl, upstreamRequest) {
        assert.equal(upstreamRequest.url, "https://example.invalid/codex/responses");
        return new Response("data: hello\n\n", {
          status: 200,
          headers: {
            "content-type": "text/event-stream"
          }
        });
      },
      createAbortSignal() {
        return new AbortController().signal;
      }
    }
  );

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
    const originalBody = JSON.stringify({
      model: "gpt-5.4",
      stream: true,
      input: [{ role: "user", content: [{ type: "input_text", text: "hello" }] }]
    });
    const bodyBuffer = Buffer.from(originalBody, "utf8");
    const chunkSize = Math.ceil(bodyBuffer.length / 2);
    const firstChunk = bodyBuffer.subarray(0, chunkSize);
    const secondChunk = bodyBuffer.subarray(chunkSize);

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
        headers: {
          authorization: "Bearer inbound",
          "x-session-id": "sess_1",
          "content-type": "application/json"
        },
        headerAllowlist: ["authorization", "x-session-id", "content-type"],
        bodySize: bodyBuffer.length,
        bodySha256: sha256Hex(bodyBuffer),
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
    assert.equal(captured.requestBody.model, "gpt-5.4");
    assert.equal(captured.requestHeaders["x-session-id"], "sess_1");
    assert.equal(captured.credentials.accountId, "acc_test");
  } finally {
    await close(server);
    await rm(storageDir, { recursive: true, force: true });
  }
});

test("relay rejects chunk with bad checksum", async () => {
  const storageDir = await mkdtemp(join(tmpdir(), "codex-relay-"));
  const relayHandlers = createRelayHandlers(
    {
      relayStorageDir: storageDir,
      relayRequestTtlMs: 60_000,
      relaySharedSecret: "secret",
      codexDefaultModel: "gpt-5.4",
      codexAllowedModels: ["gpt-5.4"],
      codexBaseUrl: "https://chatgpt.com/backend-api",
      codexOriginator: "codex-proxy"
    },
    {
      tokenManager: { async getCredentials() { return { accessToken: "token", accountId: "acc" }; } },
      buildUpstreamRequest() { throw new Error("should not be called"); },
      sendToCodex() { throw new Error("should not be called"); },
      createAbortSignal() { return new AbortController().signal; }
    }
  );

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
        headers: {},
        headerAllowlist: [],
        bodySize: 5,
        bodySha256: "",
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

  const relayHandlers = createRelayHandlers(
    {
      relayStorageDir: storageDir,
      relayRequestTtlMs: 60_000,
      relaySharedSecret: "secret",
      codexDefaultModel: "gpt-5.4",
      codexAllowedModels: ["gpt-5.4"],
      codexBaseUrl: "https://chatgpt.com/backend-api",
      codexOriginator: "codex-proxy"
    },
    {
      tokenManager: {
        async getCredentials() {
          throw new Error("should not request codex credentials for generic forwarding");
        }
      },
      buildUpstreamRequest() {
        throw new Error("should not build codex request for generic forwarding");
      },
      sendToCodex() {
        throw new Error("should not use codex sender for generic forwarding");
      },
      createAbortSignal() {
        return new AbortController().signal;
      }
    }
  );

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
    captured.url = url;
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
        headerAllowlist: ["content-type", "statsig-api-key", "user-agent"],
        bodySize: bodyBuffer.length,
        bodySha256: sha256Hex(bodyBuffer),
        chunkCount: 1
      })
    });
    assert.equal(response.status, 202);

    response = await fetch(`${baseUrl}/relay/v1/chunked/chunks/req_metrics/0`, {
      method: "PUT",
      headers: {
        "x-relay-secret": "secret",
        "x-chunk-size": String(bodyBuffer.length),
        "x-chunk-sha256": sha256Hex(bodyBuffer)
      },
      body: bodyBuffer
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
