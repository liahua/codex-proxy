import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { WebSocketServer, WebSocket } from "ws";
import { attachWebSocketRelay } from "../src/ws-relay.js";

function sha256Hex(content) {
  return createHash("sha256").update(content).digest("hex");
}

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

async function openWebSocket(url, options = {}) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, options);
    socket.once("open", () => resolve(socket));
    socket.once("error", reject);
  });
}

async function onceMessage(socket) {
  return new Promise((resolve) => {
    socket.once("message", (data, isBinary) => resolve({ data, isBinary }));
  });
}

async function onceClose(socket) {
  return new Promise((resolve) => {
    socket.once("close", (code, reason) => resolve({ code, reason: reason.toString() }));
  });
}

test("ws relay reassembles client chunks and forwards upstream responses", async () => {
  const upstreamServer = createServer();
  const upstreamWss = new WebSocketServer({ server: upstreamServer, path: "/upstream" });
  const relayServer = createServer();
  attachWebSocketRelay(relayServer, { relaySharedSecret: "secret" });

  const upstreamAddress = await listen(upstreamServer);
  const relayAddress = await listen(relayServer);
  const upstreamUrl = `ws://127.0.0.1:${upstreamAddress.port}/upstream`;
  const relayUrl = `ws://127.0.0.1:${relayAddress.port}/relay/v1/codex/ws`;
  const originalPayload = JSON.stringify({
    type: "response.create",
    input: "hello from relay"
  });
  const payloadBuffer = Buffer.from(originalPayload, "utf8");
  const chunkSize = Math.ceil(payloadBuffer.length / 2);

  const upstreamConnection = new Promise((resolve) => {
    upstreamWss.once("connection", (socket, request) => resolve({ socket, request }));
  });

  try {
    const clientSocket = await openWebSocket(relayUrl, {
      headers: {
        authorization: "Bearer test-token",
        "chatgpt-account-id": "acc_test",
        "x-relay-secret": "secret",
        "x-relay-upstream-url": upstreamUrl
      }
    });

    const { socket: upstreamSocket, request: upstreamRequest } = await upstreamConnection;
    assert.equal(upstreamRequest.headers.authorization, "Bearer test-token");
    assert.equal(upstreamRequest.headers["chatgpt-account-id"], "acc_test");
    assert.equal(upstreamRequest.headers["x-relay-secret"], undefined);
    assert.equal(upstreamRequest.headers["x-relay-upstream-url"], undefined);

    const upstreamMessagePromise = onceMessage(upstreamSocket);
    for (let index = 0; index < 2; index += 1) {
      const start = index * chunkSize;
      const end = start + chunkSize;
      const chunk = payloadBuffer.subarray(start, end);
      clientSocket.send(
        JSON.stringify({
          __relay_chunk_v1: {
            id: "chunk_ok",
            index,
            total: 2,
            sha256: sha256Hex(payloadBuffer),
            total_bytes: payloadBuffer.length,
            is_text: true
          },
          data: chunk.toString("base64")
        })
      );
    }

    const upstreamMessage = await upstreamMessagePromise;
    assert.equal(upstreamMessage.isBinary, false);
    assert.equal(upstreamMessage.data.toString("utf8"), originalPayload);

    upstreamSocket.send(JSON.stringify({ type: "response.completed", text: "ping" }));
    const clientMessage = await onceMessage(clientSocket);
    assert.equal(clientMessage.data.toString("utf8"), '{"type":"response.completed","text":"ping"}');

    clientSocket.close();
    upstreamSocket.close();
  } finally {
    upstreamWss.close();
    await close(relayServer);
    await close(upstreamServer);
  }
});

test("ws relay closes both sockets when assembled checksum mismatches", async () => {
  const upstreamServer = createServer();
  const upstreamWss = new WebSocketServer({ server: upstreamServer, path: "/upstream" });
  const relayServer = createServer();
  attachWebSocketRelay(relayServer, { relaySharedSecret: "secret" });

  const upstreamAddress = await listen(upstreamServer);
  const relayAddress = await listen(relayServer);
  const upstreamUrl = `ws://127.0.0.1:${upstreamAddress.port}/upstream`;
  const relayUrl = `ws://127.0.0.1:${relayAddress.port}/relay/v1/codex/ws`;
  const originalPayload = Buffer.from('{"type":"response.create","input":"checksum"}', "utf8");
  const chunkSize = Math.ceil(originalPayload.length / 2);

  const upstreamConnection = new Promise((resolve) => {
    upstreamWss.once("connection", (socket) => resolve(socket));
  });

  try {
    const clientSocket = await openWebSocket(relayUrl, {
      headers: {
        "x-relay-secret": "secret",
        "x-relay-upstream-url": upstreamUrl
      }
    });

    const upstreamSocket = await upstreamConnection;
    const clientClosePromise = onceClose(clientSocket);
    const upstreamClosePromise = onceClose(upstreamSocket);

    for (let index = 0; index < 2; index += 1) {
      const start = index * chunkSize;
      const end = start + chunkSize;
      const chunk = originalPayload.subarray(start, end);
      clientSocket.send(
        JSON.stringify({
          __relay_chunk_v1: {
            id: "chunk_bad",
            index,
            total: 2,
            sha256: "bad",
            total_bytes: originalPayload.length,
            is_text: true
          },
          data: chunk.toString("base64")
        })
      );
    }

    const clientClose = await clientClosePromise;
    const upstreamClose = await upstreamClosePromise;
    assert.equal(clientClose.code, 1011);
    assert.equal(clientClose.reason, "relay_checksum_mismatch");
    assert.equal(upstreamClose.code, 1011);
    assert.equal(upstreamClose.reason, "relay_checksum_mismatch");
  } finally {
    upstreamWss.close();
    await close(relayServer);
    await close(upstreamServer);
  }
});
