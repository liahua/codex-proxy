import {
  brotliDecompressSync,
  gunzipSync,
  inflateSync,
  zstdDecompressSync
} from "node:zlib";

const HOP_BY_HOP_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "proxy-connection",
  "transfer-encoding",
  "content-length"
]);

// Headers that only make sense when talking to chatgpt.com directly. When the
// relay re-targets a request at CPA they are either meaningless or actively
// harmful (a stale ChatGPT bearer would shadow the CPA api key).
const CPA_STRIPPED_REQUEST_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "chatgpt-account-id",
  "cookie",
  "x-relay-secret",
  "x-relay-response-encrypt",
  "accept-encoding"
]);

// chatgpt.com path -> CPA path. CPA serves both the OpenAI-style /v1 routes
// and the /backend-api/codex aliases, so everything folds onto /v1.
const CODEX_PATH_MAP = new Map([
  ["/backend-api/codex/responses", "/v1/responses"],
  ["/backend-api/codex/responses/compact", "/v1/responses/compact"],
  ["/backend-api/codex/models", "/v1/models"],
  ["/v1/responses", "/v1/responses"],
  ["/v1/responses/compact", "/v1/responses/compact"],
  ["/v1/models", "/v1/models"]
]);

function normalizeBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function buildHeaders(headers, { strip = new Set() } = {}) {
  const forwarded = new Headers();
  for (const [key, value] of Object.entries(headers || {})) {
    const lowered = key.toLowerCase();
    if (typeof value !== "string") {
      continue;
    }
    if (HOP_BY_HOP_REQUEST_HEADERS.has(lowered) || strip.has(lowered)) {
      continue;
    }
    forwarded.set(lowered, value);
  }
  return forwarded;
}

/**
 * Map a chatgpt.com Codex path onto the equivalent CPA path.
 * Returns "" when the path is not a Codex responses endpoint.
 */
export function mapCodexPathToCpa(pathname) {
  const path = String(pathname || "").split("?", 1)[0];
  const exact = CODEX_PATH_MAP.get(path);
  if (exact) {
    return exact;
  }
  for (const [suffix, mapped] of CODEX_PATH_MAP) {
    if (path.endsWith(suffix)) {
      return mapped;
    }
  }
  return "";
}

const UNCHANGED = { changed: false, model: "", mappedModel: "", strippedTools: [] };

const BODY_DECODERS = {
  gzip: gunzipSync,
  deflate: inflateSync,
  br: brotliDecompressSync,
  zstd: zstdDecompressSync
};

/**
 * The Codex CLI compresses request bodies (zstd in current versions), so the
 * body has to be decoded before anything can be read out of it. Returns null
 * when the encoding is unknown or the payload is not JSON we can rewrite.
 */
function decodeRequestBody(bodyBuffer, contentEncoding) {
  const encoding = String(contentEncoding || "").trim().toLowerCase();
  if (!encoding || encoding === "identity") {
    return bodyBuffer;
  }
  const decoder = BODY_DECODERS[encoding];
  if (!decoder) {
    return null;
  }
  try {
    return decoder(bodyBuffer);
  } catch {
    return null;
  }
}

/**
 * Adapts a Codex request body to what CPA will accept:
 *  - maps Codex model ids onto ones CPA actually serves
 *  - drops client tools that collide with the hosted tools CPA injects.
 *    The Codex CLI ships an `image_gen` namespace tool, and CPA adds a hosted
 *    `image_generation` tool; sending both makes the upstream reject the whole
 *    request with "conflicts with a hosted tool in the same request".
 */
function rewriteBodyForCpa(config, bodyBuffer, contentEncoding) {
  const stripToolNames = config.cpaStripToolNames || [];
  const hasModelRewrite = Object.keys(config.cpaModelMap || {}).length > 0 || config.cpaForceModel;
  if (!hasModelRewrite && stripToolNames.length === 0) {
    return { body: bodyBuffer, ...UNCHANGED };
  }

  const decodedBody = decodeRequestBody(bodyBuffer, contentEncoding);
  if (!decodedBody) {
    return { body: bodyBuffer, ...UNCHANGED, undecodable: true };
  }

  let parsed;
  try {
    parsed = JSON.parse(decodedBody.toString("utf8"));
  } catch {
    return { body: bodyBuffer, ...UNCHANGED };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { body: bodyBuffer, ...UNCHANGED };
  }

  let changed = false;

  const model = typeof parsed.model === "string" ? parsed.model : "";
  const mappedModel = config.cpaForceModel || config.cpaModelMap?.[model] || "";
  if (mappedModel && mappedModel !== model) {
    parsed.model = mappedModel;
    changed = true;
  }

  const strippedTools = [];
  if (stripToolNames.length > 0 && Array.isArray(parsed.tools)) {
    const kept = parsed.tools.filter((tool) => {
      const name = tool && typeof tool.name === "string" ? tool.name : "";
      if (name && stripToolNames.includes(name)) {
        strippedTools.push(name);
        return false;
      }
      return true;
    });
    if (strippedTools.length > 0) {
      parsed.tools = kept;
      changed = true;
    }
  }

  if (!changed) {
    return { body: bodyBuffer, ...UNCHANGED, model };
  }

  return {
    body: Buffer.from(JSON.stringify(parsed), "utf8"),
    changed: true,
    model,
    mappedModel: mappedModel && mappedModel !== model ? mappedModel : "",
    strippedTools
  };
}

/**
 * Decides where an assembled relay request actually goes.
 *
 * passthrough mode keeps the historical behaviour: send it to whatever
 * targetUrl the client recorded. cpa mode re-points Codex responses traffic at
 * CPA (which owns the real OpenAI credentials) and swaps in the CPA api key.
 */
export function createUpstreamRouter(config) {
  const cpaBaseUrl = normalizeBaseUrl(config.cpaBaseUrl);

  function resolve(metadata, bodyBuffer) {
    const targetUrl = typeof metadata.targetUrl === "string" ? metadata.targetUrl : "";
    const method = typeof metadata.method === "string" ? metadata.method : "POST";

    if (config.relayUpstreamMode !== "cpa") {
      if (!targetUrl) {
        throw new Error("relay targetUrl is required for generic forwarding");
      }
      return {
        url: targetUrl,
        method,
        headers: buildHeaders(metadata.headers),
        body: bodyBuffer,
        routed: false,
        reason: "passthrough"
      };
    }

    if (!cpaBaseUrl) {
      throw new Error("CPA_BASE_URL is required when RELAY_UPSTREAM_MODE=cpa");
    }

    let pathname = typeof metadata.path === "string" ? metadata.path : "";
    if (targetUrl) {
      try {
        pathname = new URL(targetUrl).pathname;
      } catch {
        // keep the recorded path when targetUrl is not a valid absolute URL
      }
    }

    const cpaPath = mapCodexPathToCpa(pathname);
    if (!cpaPath) {
      if (config.cpaDropUnmatched) {
        return { drop: true, routed: false, reason: "unmatched-dropped", url: targetUrl, method };
      }
      if (!targetUrl) {
        throw new Error("relay targetUrl is required for generic forwarding");
      }
      return {
        url: targetUrl,
        method,
        headers: buildHeaders(metadata.headers),
        body: bodyBuffer,
        routed: false,
        reason: "unmatched-passthrough"
      };
    }

    const headers = buildHeaders(metadata.headers, { strip: CPA_STRIPPED_REQUEST_HEADERS });
    if (config.cpaApiKey) {
      headers.set("authorization", `Bearer ${config.cpaApiKey}`);
    }
    if (!headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }
    if (!headers.has("accept")) {
      headers.set("accept", "text/event-stream");
    }

    const rewritten = rewriteBodyForCpa(config, bodyBuffer, metadata.headers?.["content-encoding"]);
    if (rewritten.changed) {
      // The body was re-serialized as plain JSON, so any encoding the client
      // declared no longer describes what we are about to send.
      headers.delete("content-encoding");
      headers.delete("content-md5");
    }

    return {
      url: `${cpaBaseUrl}${cpaPath}`,
      method,
      headers,
      body: rewritten.body,
      routed: true,
      reason: "cpa",
      model: rewritten.model,
      mappedModel: rewritten.mappedModel,
      strippedTools: rewritten.strippedTools,
      ...(rewritten.undecodable ? { undecodableBody: true } : {})
    };
  }

  return { resolve };
}
