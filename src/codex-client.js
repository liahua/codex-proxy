function normalizeBaseUrl(baseUrl) {
  const trimmed = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!trimmed) {
    return "https://chatgpt.com/backend-api/codex/responses";
  }
  if (trimmed.endsWith("/codex/responses")) {
    return trimmed;
  }
  if (trimmed.endsWith("/codex")) {
    return `${trimmed}/responses`;
  }
  return `${trimmed}/codex/responses`;
}

function validateModel(model, allowedModels) {
  if (!model || typeof model !== "string") {
    throw new Error("Request body must include a model");
  }
  if (allowedModels.length > 0 && !allowedModels.includes(model)) {
    throw new Error(`Model is not allowed by proxy policy: ${model}`);
  }
}

export function buildUpstreamRequest(config, body, credentials, requestHeaders = {}) {
  const sessionId =
    requestHeaders["x-session-id"] ||
    requestHeaders["x-codex-session-id"] ||
    (typeof body.prompt_cache_key === "string" ? body.prompt_cache_key : undefined);

  const normalizedBody = {
    ...body,
    model: body.model || config.codexDefaultModel,
    store: typeof body.store === "boolean" ? body.store : false
  };

  validateModel(normalizedBody.model, config.codexAllowedModels);

  if (sessionId && normalizedBody.prompt_cache_key === undefined) {
    normalizedBody.prompt_cache_key = sessionId;
  }
  if (sessionId && normalizedBody.prompt_cache_retention === undefined) {
    normalizedBody.prompt_cache_retention = "in-memory";
  }

  const acceptsStreaming = normalizedBody.stream !== false;
  const headers = new Headers({
    Authorization: `Bearer ${credentials.accessToken}`,
    "chatgpt-account-id": credentials.accountId,
    "OpenAI-Beta": "responses=experimental",
    originator: config.codexOriginator,
    "User-Agent": `codex-proxy (${process.platform} ${process.arch})`,
    "content-type": "application/json",
    accept: acceptsStreaming ? "text/event-stream" : "application/json"
  });

  if (sessionId) {
    headers.set("session_id", sessionId);
    headers.set("conversation_id", sessionId);
  }

  return {
    url: normalizeBaseUrl(config.codexBaseUrl),
    headers,
    body: normalizedBody
  };
}

export async function sendToCodex(fetchImpl, upstreamRequest, signal) {
  return fetchImpl(upstreamRequest.url, {
    method: "POST",
    headers: upstreamRequest.headers,
    body: JSON.stringify(upstreamRequest.body),
    signal
  });
}
