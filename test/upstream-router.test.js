import test from "node:test";
import assert from "node:assert/strict";
import { gzipSync, zstdCompressSync } from "node:zlib";
import { createUpstreamRouter, mapCodexPathToCpa } from "../src/upstream-router.js";

const CPA_CONFIG = {
  relayUpstreamMode: "cpa",
  cpaBaseUrl: "http://cli-proxy-api:8317",
  cpaApiKey: "cpa-key",
  cpaModelMap: {},
  cpaForceModel: "",
  cpaDropUnmatched: false,
  cpaStripToolNames: []
};

function headerObject(headers) {
  return Object.fromEntries(headers.entries());
}

test("maps every codex responses path onto the CPA path", () => {
  assert.equal(mapCodexPathToCpa("/backend-api/codex/responses"), "/v1/responses");
  assert.equal(mapCodexPathToCpa("/backend-api/codex/responses/compact"), "/v1/responses/compact");
  assert.equal(mapCodexPathToCpa("/v1/responses"), "/v1/responses");
  assert.equal(mapCodexPathToCpa("/v1/responses?stream=true"), "/v1/responses");
  assert.equal(mapCodexPathToCpa("/otlp/v1/metrics"), "");
});

test("passthrough mode keeps the recorded target url and headers", () => {
  const router = createUpstreamRouter({ relayUpstreamMode: "passthrough" });
  const body = Buffer.from('{"model":"gpt-5.4"}', "utf8");
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: {
        authorization: "Bearer chatgpt-token",
        "content-encoding": "zstd",
        host: "chatgpt.com"
      }
    },
    body
  );

  assert.equal(resolved.routed, false);
  assert.equal(resolved.url, "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(resolved.body, body);
  const headers = headerObject(resolved.headers);
  assert.equal(headers.authorization, "Bearer chatgpt-token");
  assert.equal(headers["content-encoding"], "zstd");
  assert.equal(headers.host, undefined);
});

test("cpa mode retargets codex traffic and swaps in the CPA api key", () => {
  const router = createUpstreamRouter(CPA_CONFIG);
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: {
        authorization: "Bearer chatgpt-token",
        "chatgpt-account-id": "acct_123",
        cookie: "session=1",
        "x-relay-secret": "secret",
        "x-session-id": "sess_1",
        "content-type": "application/json"
      }
    },
    Buffer.from('{"model":"gpt-5.4"}', "utf8")
  );

  assert.equal(resolved.routed, true);
  assert.equal(resolved.url, "http://cli-proxy-api:8317/v1/responses");
  const headers = headerObject(resolved.headers);
  assert.equal(headers.authorization, "Bearer cpa-key");
  assert.equal(headers["chatgpt-account-id"], undefined);
  assert.equal(headers.cookie, undefined);
  assert.equal(headers["x-relay-secret"], undefined);
  assert.equal(headers["x-session-id"], "sess_1");
});

test("cpa mode rewrites mapped models inside a gzipped body and clears the stale encoding", () => {
  const router = createUpstreamRouter({
    ...CPA_CONFIG,
    cpaModelMap: { "gpt-5.1-codex": "gpt-5.5" }
  });
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: { "content-encoding": "gzip" }
    },
    gzipSync(Buffer.from(JSON.stringify({ model: "gpt-5.1-codex", stream: true }), "utf8"))
  );

  assert.equal(resolved.model, "gpt-5.1-codex");
  assert.equal(resolved.mappedModel, "gpt-5.5");
  assert.deepEqual(JSON.parse(resolved.body.toString("utf8")), { model: "gpt-5.5", stream: true });
  assert.equal(headerObject(resolved.headers)["content-encoding"], undefined);
});

test("cpa mode reads through the zstd encoding the Codex CLI actually uses", () => {
  const router = createUpstreamRouter({ ...CPA_CONFIG, cpaStripToolNames: ["image_gen"] });
  const body = {
    model: "gpt-5.5",
    tools: [{ type: "function", name: "exec_command" }, { type: "namespace", name: "image_gen" }]
  };
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: { "content-encoding": "zstd" }
    },
    zstdCompressSync(Buffer.from(JSON.stringify(body), "utf8"))
  );

  assert.deepEqual(resolved.strippedTools, ["image_gen"]);
  assert.deepEqual(JSON.parse(resolved.body.toString("utf8")).tools, [
    { type: "function", name: "exec_command" }
  ]);
  assert.equal(headerObject(resolved.headers)["content-encoding"], undefined);
});

test("cpa mode forwards a body it cannot decode instead of corrupting it", () => {
  const router = createUpstreamRouter({ ...CPA_CONFIG, cpaStripToolNames: ["image_gen"] });
  const body = Buffer.from("not really compressed", "utf8");
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: { "content-encoding": "zstd" }
    },
    body
  );

  assert.equal(resolved.body, body);
  assert.equal(resolved.undecodableBody, true);
  assert.equal(headerObject(resolved.headers)["content-encoding"], "zstd");
});

test("cpa mode leaves an unmapped model and its encoded body untouched", () => {
  const router = createUpstreamRouter({
    ...CPA_CONFIG,
    cpaModelMap: { "gpt-5.1-codex": "gpt-5.5" }
  });
  const body = Buffer.from(JSON.stringify({ model: "gpt-5.5" }), "utf8");
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/v1/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: { "content-encoding": "gzip" }
    },
    body
  );

  assert.equal(resolved.mappedModel, "");
  assert.equal(resolved.body, body);
  assert.equal(headerObject(resolved.headers)["content-encoding"], "gzip");
});

test("cpa mode passes non-codex traffic through untouched by default", () => {
  const router = createUpstreamRouter(CPA_CONFIG);
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/otlp/v1/metrics",
      targetUrl: "https://ab.chatgpt.com/otlp/v1/metrics",
      headers: { authorization: "Bearer chatgpt-token" }
    },
    Buffer.from("{}", "utf8")
  );

  assert.equal(resolved.routed, false);
  assert.equal(resolved.reason, "unmatched-passthrough");
  assert.equal(resolved.url, "https://ab.chatgpt.com/otlp/v1/metrics");
  assert.equal(headerObject(resolved.headers).authorization, "Bearer chatgpt-token");
});

test("cpa mode can drop non-codex traffic instead of leaking it upstream", () => {
  const router = createUpstreamRouter({ ...CPA_CONFIG, cpaDropUnmatched: true });
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/otlp/v1/metrics",
      targetUrl: "https://ab.chatgpt.com/otlp/v1/metrics",
      headers: {}
    },
    Buffer.from("{}", "utf8")
  );

  assert.equal(resolved.drop, true);
});

test("cpa mode refuses to start without a base url", () => {
  const router = createUpstreamRouter({ ...CPA_CONFIG, cpaBaseUrl: "" });
  assert.throws(
    () =>
      router.resolve(
        { method: "POST", path: "/v1/responses", targetUrl: "https://chatgpt.com/v1/responses", headers: {} },
        Buffer.from("{}", "utf8")
      ),
    /CPA_BASE_URL is required/
  );
});

test("cpa mode strips client tools that collide with CPA's hosted tools", () => {
  const router = createUpstreamRouter({ ...CPA_CONFIG, cpaStripToolNames: ["image_gen"] });
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/backend-api/codex/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: {}
    },
    Buffer.from(
      JSON.stringify({
        model: "gpt-5.5",
        tools: [
          { type: "function", name: "exec_command" },
          { type: "namespace", name: "image_gen", tools: [{ name: "imagegen" }] },
          { type: "web_search" }
        ]
      }),
      "utf8"
    )
  );

  assert.deepEqual(resolved.strippedTools, ["image_gen"]);
  const body = JSON.parse(resolved.body.toString("utf8"));
  assert.deepEqual(
    body.tools.map((tool) => tool.name ?? tool.type),
    ["exec_command", "web_search"]
  );
});

test("cpa mode leaves the body alone when no tool collides", () => {
  const router = createUpstreamRouter({ ...CPA_CONFIG, cpaStripToolNames: ["image_gen"] });
  const body = Buffer.from(JSON.stringify({ model: "gpt-5.5", tools: [{ name: "exec_command" }] }), "utf8");
  const resolved = router.resolve(
    {
      method: "POST",
      path: "/v1/responses",
      targetUrl: "https://chatgpt.com/backend-api/codex/responses",
      headers: {}
    },
    body
  );

  assert.deepEqual(resolved.strippedTools, []);
  assert.equal(resolved.body, body, "an untouched body must not be re-serialized");
});
