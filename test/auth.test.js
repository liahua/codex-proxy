import test from "node:test";
import assert from "node:assert/strict";
import { CodexTokenManager, decodeTokenClaims, extractBearerToken } from "../src/codex-auth.js";
import { buildUpstreamRequest } from "../src/codex-client.js";

function createToken(accountId, expSeconds = Math.floor(Date.now() / 1000) + 3600) {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      exp: expSeconds,
      "https://api.openai.com/auth": {
        chatgpt_account_id: accountId
      }
    })
  ).toString("base64url");
  return `${header}.${payload}.sig`;
}

test("extractBearerToken parses Authorization header", () => {
  assert.equal(extractBearerToken("Bearer abc.def"), "abc.def");
  assert.equal(extractBearerToken("Basic xyz"), null);
});

test("decodeTokenClaims extracts account id", () => {
  const token = createToken("acc_test");
  const claims = decodeTokenClaims(token);
  assert.equal(claims.accountId, "acc_test");
  assert.ok(claims.expiresAt > Date.now());
});

test("CodexTokenManager accepts inbound bearer token when enabled", async () => {
  const token = createToken("acc_request");
  const manager = new CodexTokenManager({
    allowClientAuthBearer: true,
    codexAccessToken: "",
    codexRefreshToken: "",
    codexClientId: "client"
  });

  const credentials = await manager.getCredentials({ authorization: `Bearer ${token}` });
  assert.equal(credentials.accountId, "acc_request");
  assert.equal(credentials.source, "request");
});

test("CodexTokenManager refreshes token", async () => {
  const token = createToken("acc_refresh");
  const manager = new CodexTokenManager(
    {
      allowClientAuthBearer: false,
      codexAccessToken: "",
      codexRefreshToken: "refresh_123",
      codexClientId: "client_123",
      codexAccountId: ""
    },
    async (url, init) => {
      assert.equal(url, "https://auth.openai.com/oauth/token");
      assert.equal(init.method, "POST");
      return new Response(
        JSON.stringify({
          access_token: token,
          expires_in: 3600
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
  );

  const credentials = await manager.getCredentials();
  assert.equal(credentials.accountId, "acc_refresh");
  assert.equal(credentials.source, "refresh-token");
});

test("buildUpstreamRequest injects Codex headers and session ids", () => {
  const request = buildUpstreamRequest(
    {
      codexBaseUrl: "https://chatgpt.com/backend-api",
      codexDefaultModel: "gpt-5.4",
      codexAllowedModels: ["gpt-5.4"],
      codexOriginator: "codex-proxy"
    },
    {
      stream: true,
      input: [],
      prompt_cache_key: "sess_1"
    },
    {
      accessToken: createToken("acc_test"),
      accountId: "acc_test"
    },
    {}
  );

  assert.equal(request.url, "https://chatgpt.com/backend-api/codex/responses");
  assert.equal(request.headers.get("chatgpt-account-id"), "acc_test");
  assert.equal(request.headers.get("OpenAI-Beta"), "responses=experimental");
  assert.equal(request.headers.get("conversation_id"), "sess_1");
  assert.equal(request.body.prompt_cache_retention, "in-memory");
});
