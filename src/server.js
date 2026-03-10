import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { loadConfig } from "./config.js";
import { CodexTokenManager } from "./codex-auth.js";
import { buildUpstreamRequest, sendToCodex } from "./codex-client.js";
import { createRelayHandlers } from "./relay.js";
import { attachWebSocketRelay } from "./ws-relay.js";

const config = loadConfig();
const tokenManager = new CodexTokenManager(config);
const relayHandlers = createRelayHandlers(config, {
  tokenManager,
  buildUpstreamRequest,
  sendToCodex,
  createAbortSignal
});

function json(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload, null, 2));
}

function getRequestHeaders(request) {
  const headers = {};
  for (const [key, value] of Object.entries(request.headers)) {
    if (typeof value === "string") {
      headers[key] = value;
    }
  }
  return headers;
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

function createAbortSignal(request) {
  const controller = new AbortController();
  request.on("close", () => controller.abort());
  request.on("aborted", () => controller.abort());
  return controller.signal;
}

function sha256Hex(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

async function handleMockCodex(request, response) {
  const rawBody = await readRawBody(request);
  const body = JSON.parse(rawBody.toString("utf8"));
  const bodySha = sha256Hex(rawBody);
  const bodyBytes = rawBody.length;
  const text = `mock-codex-ok sha256=${bodySha} bytes=${bodyBytes} model=${body.model || "unknown"}`;

  if (body.stream === false) {
    json(response, 200, {
      id: "resp_mock",
      object: "response",
      status: "completed",
      output_text: text,
      model: body.model || null,
      usage: {
        input_tokens: 0,
        output_tokens: 0,
        total_tokens: 0
      }
    });
    return;
  }

  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive"
  });

  const events = [
    {
      type: "response.output_item.added",
      item: { type: "message", id: "msg_mock_1", role: "assistant", status: "in_progress", content: [] }
    },
    {
      type: "response.content_part.added",
      part: { type: "output_text", text: "" }
    },
    {
      type: "response.output_text.delta",
      delta: text
    },
    {
      type: "response.output_item.done",
      item: {
        type: "message",
        id: "msg_mock_1",
        role: "assistant",
        status: "completed",
        content: [{ type: "output_text", text }]
      }
    },
    {
      type: "response.completed",
      response: {
        status: "completed",
        usage: {
          input_tokens: 0,
          output_tokens: 0,
          total_tokens: 0,
          input_tokens_details: { cached_tokens: 0 }
        }
      }
    }
  ];

  for (const event of events) {
    response.write(`data: ${JSON.stringify(event)}\n\n`);
  }
  response.end();
}

async function handleResponses(request, response) {
  const requestHeaders = getRequestHeaders(request);
  const requestBody = await readJsonBody(request);
  const credentials = await tokenManager.getCredentials(requestHeaders);
  const upstreamRequest = buildUpstreamRequest(config, requestBody, credentials, requestHeaders);
  const upstream = await sendToCodex(fetch, upstreamRequest, createAbortSignal(request));

  const headers = proxyResponseHeaders(upstream);
  response.writeHead(upstream.status, headers);

  if (!upstream.body) {
    response.end();
    return;
  }

  for await (const chunk of upstream.body) {
    response.write(chunk);
  }
  response.end();
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

    if (await relayHandlers.maybeHandle(request, response, url)) {
      return;
    }

    if (request.method === "GET" && url.pathname === "/healthz") {
      json(response, 200, {
        ok: true,
        upstream: config.codexBaseUrl,
        defaultModel: config.codexDefaultModel,
        relayStorageDir: config.relayStorageDir
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/mock/codex/responses") {
      await handleMockCodex(request, response);
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/models") {
      json(response, 200, {
        object: "list",
        data: config.codexAllowedModels.map((id) => ({
          id,
          object: "model",
          owned_by: "openai-codex"
        }))
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/v1/responses") {
      await handleResponses(request, response);
      return;
    }

    json(response, 404, {
      error: {
        message: `Route not found: ${request.method} ${url.pathname}`
      }
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    json(response, 500, {
      error: {
        message
      }
    });
  }
});

attachWebSocketRelay(server, config);

server.listen(config.port, config.host, () => {
  console.log(`codex-proxy listening on http://${config.host}:${config.port}`);
});
