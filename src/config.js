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

export function loadConfig() {
  loadEnvFile();

  return {
    host: process.env.HOST || "0.0.0.0",
    port: asNumber(process.env.PORT, 8787),
    relayStorageDir: process.env.RELAY_STORAGE_DIR || "./data/chunked-requests",
    relayRequestTtlMs: asNumber(process.env.RELAY_REQUEST_TTL_MS, 15 * 60 * 1000),
    relaySharedSecret: process.env.RELAY_SHARED_SECRET || "",
    relayDebugLog: asBoolean(process.env.RELAY_DEBUG_LOG, false),
    relayDebugLogBody: asBoolean(process.env.RELAY_DEBUG_LOG_BODY, false),
    relayDebugBodyMaxBytes: asNumber(process.env.RELAY_DEBUG_BODY_MAX_BYTES, 2048)
  };
}
