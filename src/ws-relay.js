import crypto from "node:crypto";
import { WebSocketServer, WebSocket } from "ws";

const DEFAULT_UPSTREAM_URL = "wss://chatgpt.com/backend-api/codex/responses";
const RELAY_CHUNK_FIELD = "__relay_chunk_v1";
const HOP_BY_HOP_HEADERS = new Set([
  "host",
  "connection",
  "upgrade",
  "sec-websocket-key",
  "sec-websocket-version",
  "sec-websocket-accept",
  "sec-websocket-extensions",
  "x-relay-secret",
  "x-relay-upstream-url"
]);

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function normalizeHeaderValue(value) {
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return typeof value === "string" ? value : undefined;
}

function buildUpstreamHeaders(request) {
  const headers = {};
  for (const [key, rawValue] of Object.entries(request.headers)) {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered)) {
      continue;
    }
    const value = normalizeHeaderValue(rawValue);
    if (value !== undefined) {
      headers[key] = value;
    }
  }
  return headers;
}

function parseRelayChunk(data) {
  try {
    const parsed = JSON.parse(data.toString("utf8"));
    return parsed && typeof parsed === "object" && RELAY_CHUNK_FIELD in parsed ? parsed : null;
  } catch {
    return null;
  }
}

function sendRaw(target, data, isBinary) {
  if (target.readyState !== WebSocket.OPEN) {
    return;
  }
  target.send(data, { binary: isBinary });
}

function closeBoth(client, upstream, code = 1011, reason = "relay_error") {
  try {
    if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CONNECTING) {
      client.close(code, reason);
    }
  } catch {}
  try {
    if (upstream.readyState === WebSocket.OPEN || upstream.readyState === WebSocket.CONNECTING) {
      upstream.close(code, reason);
    }
  } catch {}
}

export function attachWebSocketRelay(server, config) {
  const wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
    if (url.pathname !== "/relay/v1/codex/ws") {
      socket.destroy();
      return;
    }

    if (config.relaySharedSecret) {
      const secret = normalizeHeaderValue(request.headers["x-relay-secret"]);
      if (secret !== config.relaySharedSecret) {
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }
    }

    wss.handleUpgrade(request, socket, head, (clientSocket) => {
      wss.emit("connection", clientSocket, request);
    });
  });

  wss.on("connection", (clientSocket, request) => {
    const upstreamUrl =
      normalizeHeaderValue(request.headers["x-relay-upstream-url"]) || DEFAULT_UPSTREAM_URL;
    const upstreamHeaders = buildUpstreamHeaders(request);
    const pendingClientMessages = [];
    const chunkStates = new Map();

    const upstreamSocket = new WebSocket(upstreamUrl, {
      headers: upstreamHeaders
    });

    const flushPending = () => {
      while (pendingClientMessages.length > 0 && upstreamSocket.readyState === WebSocket.OPEN) {
        const item = pendingClientMessages.shift();
        sendRaw(upstreamSocket, item.data, item.isBinary);
      }
    };

    const handleClientPayload = (data, isBinary) => {
      const maybeChunk = parseRelayChunk(data);
      if (!maybeChunk) {
        if (upstreamSocket.readyState === WebSocket.OPEN) {
          sendRaw(upstreamSocket, data, isBinary);
        } else {
          pendingClientMessages.push({ data, isBinary });
        }
        return;
      }

      const meta = maybeChunk[RELAY_CHUNK_FIELD];
      if (!meta || typeof meta !== "object") {
        return;
      }
      const chunkId = meta.id;
      const index = meta.index;
      const total = meta.total;
      const payload = maybeChunk.data;
      if (
        typeof chunkId !== "string" ||
        typeof index !== "number" ||
        typeof total !== "number" ||
        typeof payload !== "string"
      ) {
        return;
      }

      let state = chunkStates.get(chunkId);
      if (!state) {
        state = {
          total,
          isBinary: !meta.is_text,
          sha256: typeof meta.sha256 === "string" ? meta.sha256 : "",
          totalBytes: typeof meta.total_bytes === "number" ? meta.total_bytes : 0,
          chunks: new Array(total).fill(null)
        };
        chunkStates.set(chunkId, state);
      }

      if (index < 0 || total <= 0 || index >= total) {
        return;
      }
      state.chunks[index] = Buffer.from(payload, "base64");
      const complete = state.chunks.every((chunk) => Buffer.isBuffer(chunk));
      if (!complete) {
        return;
      }

      const assembled = Buffer.concat(state.chunks);
      if (state.totalBytes && assembled.length !== state.totalBytes) {
        closeBoth(clientSocket, upstreamSocket, 1011, "relay_length_mismatch");
        return;
      }
      if (state.sha256 && sha256Hex(assembled) !== state.sha256) {
        closeBoth(clientSocket, upstreamSocket, 1011, "relay_checksum_mismatch");
        return;
      }

      chunkStates.delete(chunkId);
      console.log(`ws relay reassembled chunk_id=${chunkId} bytes=${assembled.length}`);
      if (upstreamSocket.readyState === WebSocket.OPEN) {
        sendRaw(upstreamSocket, assembled, state.isBinary);
      } else {
        pendingClientMessages.push({ data: assembled, isBinary: state.isBinary });
      }
    };

    clientSocket.on("message", (data, isBinary) => {
      handleClientPayload(data, isBinary);
    });

    upstreamSocket.on("open", () => {
      flushPending();
    });

    upstreamSocket.on("message", (data, isBinary) => {
      sendRaw(clientSocket, data, isBinary);
    });

    upstreamSocket.on("close", (code, reason) => {
      try {
        if (clientSocket.readyState === WebSocket.OPEN || clientSocket.readyState === WebSocket.CONNECTING) {
          clientSocket.close(code || 1000, reason.toString() || "");
        }
      } catch {}
    });

    clientSocket.on("close", (code, reason) => {
      try {
        if (upstreamSocket.readyState === WebSocket.OPEN || upstreamSocket.readyState === WebSocket.CONNECTING) {
          upstreamSocket.close(code || 1000, reason.toString() || "");
        }
      } catch {}
    });

    clientSocket.on("error", () => {
      closeBoth(clientSocket, upstreamSocket);
    });

    upstreamSocket.on("error", () => {
      closeBoth(clientSocket, upstreamSocket);
    });
  });

  return wss;
}
