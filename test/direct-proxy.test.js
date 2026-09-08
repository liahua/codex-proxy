import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createDirectProxyHandlers } from "../src/direct-proxy.js";

const SECRET = "shared-secret";

function createConfig(overrides = {}) {
  return {
    relaySharedSecret: SECRET,
    relayDebugLog: false,
    relayUpstreamMode: "cpa",
    cpaBaseUrl: "http://cli-proxy-api:8317",
    cpaApiKey: "cpa-key",
    cpaModelMap: {},
    cpaForceModel: "",
    cpaDropUnmatched: false,
    ...overrides
  };
}

async function withDirectServer(config, run) {
  const handlers = createDirectProxyHandlers(config, {
    createAbortSignal: () => new AbortController().signal
  });

  const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (await handlers.maybeHandle(request, response, url)) {
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  const address = await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });

  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

function stubFetch(captured, baseUrl, body = "data: ok\n\n") {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(baseUrl)) {
      return originalFetch(url, init);
    }
    captured.push({
      url: String(url),
      method: init.method,
      headers: Object.fromEntries(new Headers(init.headers).entries()),
      body: init.body ? Buffer.from(init.body).toString("utf8") : ""
    });
    return new Response(body, {
      status: 200,
      headers: { "content-type": "text/event-stream" }
    });
  };
  return () => {
    globalThis.fetch = originalFetch;
  };
}

test("direct proxy accepts the shared secret as a bearer token and hits CPA", async () => {
  const captured = [];
  await withDirectServer(createConfig(), async (baseUrl) => {
    const restore = stubFetch(captured, baseUrl);
    try {
      const response = await fetch(`${baseUrl}/backend-api/codex/responses`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${SECRET}`,
          "x-session-id": "sess_direct"
        },
        body: JSON.stringify({ model: "gpt-5.5", stream: true })
      });

      assert.equal(response.status, 200);
      assert.equal(await response.text(), "data: ok\n\n");
      assert.equal(captured.length, 1);
      assert.equal(captured[0].url, "http://cli-proxy-api:8317/v1/responses");
      assert.equal(captured[0].headers.authorization, "Bearer cpa-key");
      assert.equal(captured[0].headers["x-session-id"], "sess_direct");
    } finally {
      restore();
    }
  });
});

test("direct proxy also accepts the x-relay-secret header", async () => {
  const captured = [];
  await withDirectServer(createConfig(), async (baseUrl) => {
    const restore = stubFetch(captured, baseUrl);
    try {
      const response = await fetch(`${baseUrl}/v1/responses`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-relay-secret": SECRET },
        body: JSON.stringify({ model: "gpt-5.5" })
      });
      assert.equal(response.status, 200);
      assert.equal(captured.length, 1);
    } finally {
      restore();
    }
  });
});

test("direct proxy rejects a wrong secret without touching upstream", async () => {
  const captured = [];
  await withDirectServer(createConfig(), async (baseUrl) => {
    const restore = stubFetch(captured, baseUrl);
    try {
      const response = await fetch(`${baseUrl}/v1/responses`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer wrong" },
        body: JSON.stringify({ model: "gpt-5.5" })
      });
      assert.equal(response.status, 401);
      assert.equal(captured.length, 0);
    } finally {
      restore();
    }
  });
});

test("direct proxy forwards the model list to CPA", async () => {
  const captured = [];
  await withDirectServer(createConfig(), async (baseUrl) => {
    const restore = stubFetch(captured, baseUrl, '{"object":"list","data":[]}');
    try {
      const response = await fetch(`${baseUrl}/v1/models`, {
        headers: { authorization: `Bearer ${SECRET}` }
      });
      assert.equal(response.status, 200);
      assert.equal(captured.length, 1);
      assert.equal(captured[0].url, "http://cli-proxy-api:8317/v1/models");
      assert.equal(captured[0].method, "GET");
      assert.equal(captured[0].body, "");
    } finally {
      restore();
    }
  });
});

test("direct proxy rewrites a mapped codex model id", async () => {
  const captured = [];
  await withDirectServer(
    createConfig({ cpaModelMap: { "gpt-5.1-codex": "gpt-5.5" } }),
    async (baseUrl) => {
      const restore = stubFetch(captured, baseUrl);
      try {
        const response = await fetch(`${baseUrl}/backend-api/codex/responses`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${SECRET}` },
          body: JSON.stringify({ model: "gpt-5.1-codex", stream: true })
        });
        assert.equal(response.status, 200);
        assert.deepEqual(JSON.parse(captured[0].body), { model: "gpt-5.5", stream: true });
      } finally {
        restore();
      }
    }
  );
});

test("direct proxy leaves unrelated paths to the rest of the server", async () => {
  await withDirectServer(createConfig(), async (baseUrl) => {
    const response = await fetch(`${baseUrl}/healthz`);
    assert.equal(response.status, 404);
    assert.equal(await response.text(), "not found");
  });
});
