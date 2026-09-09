import { loadEnvFile } from "./load-env.js";

function asBoolean(value, fallback = false) {
  if (value === undefined) {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function asNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function asList(value, fallback = []) {
  if (value === undefined) {
    return fallback;
  }
  return String(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseJsonMap(value) {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    const map = {};
    for (const [from, to] of Object.entries(parsed)) {
      if (typeof to === "string" && to) {
        map[from] = to;
      }
    }
    return map;
  } catch {
    return {};
  }
}

function parseEncryptionKeys(value) {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    const keys = {};
    for (const [keyId, keyValue] of Object.entries(parsed)) {
      if (typeof keyValue === "string" && keyValue) {
        keys[keyId] = keyValue;
      }
    }
    return keys;
  } catch {
    return {};
  }
}

export function loadConfig() {
  loadEnvFile();

  return {
    host: process.env.HOST || "0.0.0.0",
    port: asNumber(process.env.PORT, 8787),
    relayStorageDir: process.env.RELAY_STORAGE_DIR || "./data/chunked-requests",
    relayRequestTtlMs: asNumber(process.env.RELAY_REQUEST_TTL_MS, 15 * 60 * 1000),
    relaySnapshotTtlMs: asNumber(process.env.RELAY_SNAPSHOT_TTL_MS, 24 * 60 * 60 * 1000),
    relaySharedSecret: process.env.RELAY_SHARED_SECRET || "",
    relayEncryptionKeys: parseEncryptionKeys(process.env.RELAY_ENCRYPTION_KEYS),
    relaySnapshotKeyId: process.env.RELAY_SNAPSHOT_KEY_ID || "",
    relayMaxSnapshots: asNumber(process.env.RELAY_MAX_SNAPSHOTS, 200),
    relayKeepPerConversation: asNumber(process.env.RELAY_KEEP_PER_CONVERSATION, 2),
    relayUpstreamSslVerify: asBoolean(process.env.RELAY_UPSTREAM_SSL_VERIFY, false),
    relayDebugLog: asBoolean(process.env.RELAY_DEBUG_LOG, false),
    relayDebugLogBody: asBoolean(process.env.RELAY_DEBUG_LOG_BODY, false),
    relayDebugBodyMaxBytes: asNumber(process.env.RELAY_DEBUG_BODY_MAX_BYTES, 2048),
    relayUpstreamMode: (process.env.RELAY_UPSTREAM_MODE || "passthrough").trim().toLowerCase(),
    cpaBaseUrl: process.env.CPA_BASE_URL || "",
    cpaApiKey: process.env.CPA_API_KEY || "",
    cpaModelMap: parseJsonMap(process.env.CPA_MODEL_MAP),
    cpaForceModel: process.env.CPA_FORCE_MODEL || "",
    cpaDropUnmatched: asBoolean(process.env.CPA_DROP_UNMATCHED, false),
    cpaStripToolNames: asList(process.env.CPA_STRIP_TOOL_NAMES, ["image_gen"])
  };
}
