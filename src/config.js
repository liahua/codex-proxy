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
  if (!value) {
    return fallback;
  }
  return String(value)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function loadConfig() {
  loadEnvFile();

  return {
    host: process.env.HOST || "0.0.0.0",
    port: asNumber(process.env.PORT, 8787),
    codexBaseUrl: process.env.CODEX_BASE_URL || "https://chatgpt.com/backend-api",
    codexClientId: process.env.CODEX_CLIENT_ID || "app_EMoamEEZ73f0CkXaXp7hrann",
    codexOriginator: process.env.CODEX_ORIGINATOR || "codex-proxy",
    codexDefaultModel: process.env.CODEX_DEFAULT_MODEL || "gpt-5.4",
    codexAllowedModels: asList(process.env.CODEX_ALLOWED_MODELS, ["gpt-5.4"]),
    codexAccessToken: process.env.CODEX_ACCESS_TOKEN || "",
    codexRefreshToken: process.env.CODEX_REFRESH_TOKEN || "",
    codexAccountId: process.env.CODEX_ACCOUNT_ID || "",
    allowClientAuthBearer: asBoolean(process.env.ALLOW_CLIENT_AUTH_BEARER, false),
    relayStorageDir: process.env.RELAY_STORAGE_DIR || "./data/chunked-requests",
    relayRequestTtlMs: asNumber(process.env.RELAY_REQUEST_TTL_MS, 15 * 60 * 1000),
    relaySharedSecret: process.env.RELAY_SHARED_SECRET || ""
  };
}
