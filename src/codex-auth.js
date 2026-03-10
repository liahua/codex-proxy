const JWT_CLAIM_PATH = "https://api.openai.com/auth";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const ACCESS_TOKEN_SKEW_MS = 60_000;

function decodeBase64Url(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

export function extractBearerToken(headerValue) {
  if (!headerValue) {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(headerValue.trim());
  return match ? match[1] : null;
}

export function decodeTokenClaims(accessToken) {
  const parts = String(accessToken).split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT access token");
  }

  const payload = JSON.parse(decodeBase64Url(parts[1]));
  const accountId = payload?.[JWT_CLAIM_PATH]?.chatgpt_account_id;
  if (!accountId || typeof accountId !== "string") {
    throw new Error("Missing chatgpt_account_id in token");
  }

  const exp = typeof payload.exp === "number" ? payload.exp * 1000 : undefined;
  return { payload, accountId, expiresAt: exp };
}

export class CodexTokenManager {
  constructor(config, fetchImpl = fetch) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.cached = null;
  }

  async getCredentials(requestHeaders = {}) {
    if (this.config.allowClientAuthBearer) {
      const inboundToken = extractBearerToken(requestHeaders.authorization);
      if (inboundToken) {
        const claims = decodeTokenClaims(inboundToken);
        return {
          accessToken: inboundToken,
          accountId: claims.accountId,
          source: "request"
        };
      }
    }

    if (this.config.codexAccessToken) {
      const claims = decodeTokenClaims(this.config.codexAccessToken);
      return {
        accessToken: this.config.codexAccessToken,
        accountId: this.config.codexAccountId || claims.accountId,
        source: "env-access-token"
      };
    }

    if (!this.config.codexRefreshToken) {
      throw new Error(
        "No Codex credentials configured. Set CODEX_ACCESS_TOKEN or CODEX_REFRESH_TOKEN, or allow client bearer auth."
      );
    }

    if (this.cached && this.cached.expiresAt > Date.now() + ACCESS_TOKEN_SKEW_MS) {
      return {
        accessToken: this.cached.accessToken,
        accountId: this.cached.accountId,
        source: "refresh-cache"
      };
    }

    return this.refreshAccessToken();
  }

  async refreshAccessToken() {
    const response = await this.fetchImpl(TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: this.config.codexRefreshToken,
        client_id: this.config.codexClientId
      })
    });

    const rawText = await response.text();
    if (!response.ok) {
      throw new Error(`Codex token refresh failed: ${response.status} ${rawText}`);
    }

    const json = JSON.parse(rawText);
    if (!json.access_token || typeof json.access_token !== "string") {
      throw new Error("Codex token refresh response is missing access_token");
    }

    let accountId = this.config.codexAccountId || "";
    let expiresAt = Date.now() + (Number(json.expires_in) || 3600) * 1000;

    try {
      const claims = decodeTokenClaims(json.access_token);
      accountId = accountId || claims.accountId;
      expiresAt = claims.expiresAt || expiresAt;
    } catch (error) {
      if (!accountId) {
        throw error;
      }
    }

    if (!accountId) {
      throw new Error("Unable to resolve chatgpt account id from refresh flow");
    }

    this.cached = {
      accessToken: json.access_token,
      accountId,
      expiresAt
    };

    return {
      accessToken: json.access_token,
      accountId,
      source: "refresh-token"
    };
  }
}
