import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

function getString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

async function loadCodexAuth(authFile) {
  const raw = await readFile(authFile, "utf8");
  const parsed = JSON.parse(raw);
  const tokens = parsed && typeof parsed === "object" ? parsed.tokens : null;
  if (!tokens || typeof tokens !== "object") {
    throw new Error(`Invalid Codex auth file: ${authFile}`);
  }

  return {
    refreshToken: getString(tokens.refresh_token),
    accessToken: getString(tokens.access_token),
    accountId: getString(tokens.account_id)
  };
}

async function main() {
  const codexHome = process.env.CODEX_HOME || join(homedir(), ".codex");
  const authFile = process.env.CODEX_AUTH_FILE || join(codexHome, "auth.json");
  const auth = await loadCodexAuth(authFile);

  if (!process.env.CODEX_REFRESH_TOKEN && auth.refreshToken) {
    process.env.CODEX_REFRESH_TOKEN = auth.refreshToken;
  }
  if (!process.env.CODEX_ACCESS_TOKEN && auth.accessToken) {
    process.env.CODEX_ACCESS_TOKEN = auth.accessToken;
  }
  if (!process.env.CODEX_ACCOUNT_ID && auth.accountId) {
    process.env.CODEX_ACCOUNT_ID = auth.accountId;
  }

  if (!process.env.CODEX_REFRESH_TOKEN && !process.env.CODEX_ACCESS_TOKEN) {
    throw new Error(
      `No refresh_token or access_token found in ${authFile}. Re-login with Codex first, or set CODEX_REFRESH_TOKEN/CODEX_ACCESS_TOKEN manually.`
    );
  }

  process.env.HOST = process.env.HOST || "127.0.0.1";
  process.env.PORT = process.env.PORT || "8787";

  console.error(`Starting codex-proxy with auth from ${authFile}`);
  await import("../src/server.js");
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to start codex-proxy: ${message}`);
  process.exit(1);
});
