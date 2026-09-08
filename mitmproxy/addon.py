#!/usr/bin/env python3
"""
Codex request chunk relay addon for mitmproxy.

For matched HTTP requests, this addon always uses relay forwarding:
1. uploads request metadata to the external relay service
2. uploads the full body in chunks
3. rewrites the original request into a small /complete call

The final /complete request is forwarded by mitmproxy as usual, so the relay
service can stream the real Codex response back to the client.
"""

import json
import math
import os
import uuid
import time
import hashlib
import base64
import struct
import io
import gzip
import zlib
from datetime import datetime, timezone
from pathlib import Path

import httpx
from urllib.parse import urljoin, urlsplit, urlunsplit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mitmproxy import ctx, http

REDACTED_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-relay-secret",
}
AES_256_GCM = "aes-256-gcm"
RESPONSE_FRAME_PROTOCOL = "aes-256-gcm-frame-v1"
RESPONSE_ENCRYPTED_HEADER = "x-relay-response-encrypted"
UPSTREAM_STATUS_HEADER = "x-relay-upstream-status"
UPSTREAM_CONTENT_TYPE_HEADER = "x-relay-upstream-content-type"
INTERNAL_CONTENT_ENCODING_GZIP = "gzip"
DEFAULT_SCHEME_PORTS = {
    "http": 80,
    "https": 443,
}


class NonFallbackRelayError(RuntimeError):
    pass

try:
    import brotli
except ImportError:
    brotli = None

try:
    import zstandard
except ImportError:
    zstandard = None

def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if not normalized:
        return default
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_url(url: str):
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid URL port: {url}") from exc
    scheme = parsed.scheme
    host = parsed.hostname or ""
    if port is None:
        port = DEFAULT_SCHEME_PORTS.get(scheme.lower())
    path = parsed.path or "/"
    query = parsed.query
    return scheme, host, port, path, query


def is_default_port(scheme: str, port: int | None) -> bool:
    return port is not None and DEFAULT_SCHEME_PORTS.get((scheme or "").lower()) == port


def format_host_header(host: str, port: int | None, scheme: str = "") -> str:
    if not host:
        return host
    host_value = host
    if ":" in host and not host.startswith("["):
        host_value = f"[{host}]"
    if port is None or is_default_port(scheme, port):
        return host_value
    return f"{host_value}:{port}"


def require_url(env_name: str, url: str, allowed_schemes: set[str]) -> tuple[str, str, int, str, str]:
    scheme, host, port, path, query = parse_url(url)
    scheme = scheme.lower()
    if not scheme:
        raise ValueError(f"{env_name} must include URL scheme")
    if scheme not in allowed_schemes:
        raise ValueError(f"{env_name} scheme must be one of {sorted(allowed_schemes)}, got {scheme}")
    if not host:
        raise ValueError(f"{env_name} must include host")
    if port is None:
        raise ValueError(f"{env_name} scheme must provide a default port or include an explicit port")
    return scheme, host, port, path, query


def canonicalize_url(env_name: str, url: str, allowed_schemes: set[str]) -> str:
    scheme, host, port, path, query = require_url(env_name, url, allowed_schemes)
    netloc = format_host_header(host, port, scheme)
    return urlunsplit((scheme, netloc, path, query, ""))

class CodexChunkRelayAddon:
    def __init__(self):
        self.enabled = env_bool("CHUNK_RELAY_ENABLED", True)
        relay_base_url = os.getenv("CHUNK_RELAY_BASE_URL", "").strip().rstrip("/")
        self.relay_base_url = (
            canonicalize_url("CHUNK_RELAY_BASE_URL", relay_base_url, {"http", "https"}).rstrip("/")
            if relay_base_url
            else ""
        )
        self.shared_secret = os.getenv("CHUNK_RELAY_SHARED_SECRET", "")
        # v4 is the only wire protocol: encrypted chunks + request delta.
        self.protocol_version = "v4"
        self.encryption_key_id = os.getenv("CHUNK_RELAY_ENCRYPTION_KEY_ID", "default")
        self.encryption_key = os.getenv("CHUNK_RELAY_ENCRYPTION_KEY", "")
        self.chunk_size_bytes = env_int("CHUNK_RELAY_CHUNK_SIZE_BYTES", 20 * 1024)
        self.timeout_seconds = env_int("CHUNK_RELAY_TIMEOUT_SECONDS", 600)
        self.upload_retries = env_int("CHUNK_RELAY_UPLOAD_RETRIES", 3)
        self.retry_backoff_ms = env_int("CHUNK_RELAY_RETRY_BACKOFF_MS", 400)
        self.max_delta_snapshots = env_int("CHUNK_RELAY_MAX_DELTA_SNAPSHOTS", 32)
        self.response_ref_min_chars = env_int("CHUNK_RELAY_RESPONSE_REF_MIN_CHARS", 64)
        self.max_response_snapshots = env_int("CHUNK_RELAY_MAX_RESPONSE_SNAPSHOTS", 16)
        self.relay_ssl_verify = env_bool("CHUNK_RELAY_SSL_VERIFY", False)

        self.output_file = os.getenv("MITM_RECORD_OUTPUT_FILE", "").strip()
        self.body_max_bytes = env_int("MITM_RECORD_BODY_MAX_BYTES", 0)
        self.error_output_file = os.getenv("MITM_ERROR_LOG_FILE", "").strip()
        self.error_body_max_bytes = env_int("MITM_ERROR_BODY_MAX_BYTES", 8192)
        self.match_hosts = {
            item.strip().lower()
            for item in os.getenv("CHUNK_RELAY_MATCH_HOSTS", "127.0.0.1,localhost,chatgpt.com,ab.chatgpt.com").split(",")
            if item.strip()
        }
        self.console_log_enabled = env_bool("CHUNK_RELAY_CONSOLE_LOG", True)
        self.ws_block_status = env_int("CHUNK_RELAY_WS_BLOCK_STATUS", 501)
        self.http_client = httpx.Client(
            trust_env=True,
            verify=self.relay_ssl_verify,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

        self.delta_snapshots = []
        self.pending_snapshots = {}
        self.response_snapshots = []

        decoded_key = base64.b64decode(self.encryption_key) if self.encryption_key else b""
        if len(decoded_key) != 32:
            raise ValueError(
                "CHUNK_RELAY_ENCRYPTION_KEY must be a base64-encoded 32-byte AES key; "
                "there is no unencrypted relay mode"
            )
        self._encryption_key_bytes = decoded_key

    def host_matches(self, host: str) -> bool:
        normalized = (host or "").strip().lower().rstrip(".")
        if not normalized:
            return False

        for pattern in self.match_hosts:
            candidate = pattern.strip().lower().rstrip(".")
            if not candidate:
                continue
            if candidate.startswith("*."):
                suffix = candidate[1:]
                if normalized.endswith(suffix) and normalized != suffix[1:]:
                    return True
                continue
            if candidate.startswith("."):
                if normalized.endswith(candidate) and normalized != candidate[1:]:
                    return True
                continue
            if normalized == candidate:
                return True

        return False

    def load(self, loader):
        if self.output_file:
            Path(self.output_file).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        if self.error_output_file:
            Path(self.error_output_file).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        ctx.log.info(
            "chunk relay addon loaded: "
            f"enabled={self.enabled}, relay_base_url={self.relay_base_url or '<empty>'}, "
            f"protocol={self.protocol_version}, http_always_relay_matched=true, chunk_size={self.chunk_size_bytes}, "
            f"matched_hosts={sorted(self.match_hosts)}, ws_policy=block_503, "
            f"console_log={self.console_log_enabled}, relay_ssl_verify={self.relay_ssl_verify}, "
            f"error_output_file={self.error_output_file or '<disabled>'}"
        )

    def done(self):
        self.http_client.close()

    def _log(self, msg: str = "") -> None:
        if not self.console_log_enabled:
            return
        print(msg, flush=True)

    def _pretty_print_text(self, text: str) -> None:
        if not text:
            self._log("[Empty Body]")
            return
        try:
            self._log(json.dumps(json.loads(text), indent=2, ensure_ascii=False))
        except Exception:
            self._log(text)

    def _sanitize_header_value(self, key: str, value: str) -> str:
        if key in REDACTED_HEADER_KEYS:
            # Keep a short fingerprint so a mismatch is still debuggable, but
            # never write the secret itself into a log file.
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
            return f"<redacted sha256:{digest}>"
        return value

    def _sanitize_headers(self, headers: dict) -> dict:
        sanitized = {}
        for key, value in (headers or {}).items():
            if not isinstance(value, str):
                continue
            lowered = key.lower()
            sanitized[lowered] = self._sanitize_header_value(lowered, value)
        return sanitized

    def _bytes_preview(self, data: bytes, max_bytes: int = 2048) -> dict:
        sample = data[:max_bytes]
        truncated = len(data) > len(sample)
        try:
            text = sample.decode("utf-8")
            encoding = "utf8"
        except UnicodeDecodeError:
            text = sample.decode("utf-8", errors="replace")
            encoding = "utf8-replace"
        return {
            "encoding": encoding,
            "total_bytes": len(data),
            "truncated": truncated,
            "preview": text,
        }

    def _decode_content_encoding(self, data: bytes, content_encoding: str) -> tuple[bytes, str]:
        normalized = (content_encoding or "").strip().lower()
        if not normalized or normalized == "identity":
            return data, "identity"
        if normalized == "gzip":
            return gzip.decompress(data), "gzip"
        if normalized == "deflate":
            try:
                return zlib.decompress(data), "deflate"
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS), "deflate-raw"
        if normalized == "br":
            if brotli is None:
                raise ValueError("brotli decoder unavailable")
            return brotli.decompress(data), "br"
        if normalized == "zstd":
            if zstandard is None:
                raise ValueError("zstandard decoder unavailable")
            with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
                return reader.read(), "zstd"
        raise ValueError(f"unsupported content-encoding: {normalized}")

    def _serialize_text_candidate(self, data: bytes, *, limit: int, total_bytes: int, truncated: bool) -> dict:
        try:
            text = data.decode("utf-8")
            payload = {
                "kind": "text",
                "encoding": "utf8",
                "total_bytes": total_bytes,
                "truncated": truncated,
                "text": text,
            }
            try:
                payload["json"] = json.loads(text)
            except Exception:
                pass
            return payload
        except UnicodeDecodeError:
            return {
                "kind": "base64",
                "encoding": "base64",
                "total_bytes": total_bytes,
                "truncated": truncated,
                "base64": base64.b64encode(data[:limit] if limit > 0 else data).decode("ascii"),
            }

    def serialize_bytes(self, data: bytes, headers: dict | None = None, limit: int | None = None) -> dict:
        raw = data or b""
        total_bytes = len(raw)
        byte_limit = self.body_max_bytes if limit is None else limit
        raw_sample = raw[:byte_limit] if byte_limit > 0 else raw
        truncated = len(raw_sample) != total_bytes
        payload = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw": self._serialize_text_candidate(
                raw_sample,
                limit=byte_limit,
                total_bytes=total_bytes,
                truncated=truncated,
            ),
        }

        content_encoding = ""
        if headers:
            content_encoding = str(headers.get("content-encoding", "") or headers.get("Content-Encoding", ""))

        if content_encoding:
            try:
                decoded_bytes, decoded_via = self._decode_content_encoding(raw, content_encoding)
                decoded_total = len(decoded_bytes)
                decoded_sample = decoded_bytes[:byte_limit] if byte_limit > 0 else decoded_bytes
                payload["decoded"] = {
                    "content_encoding": content_encoding,
                    "decoded_via": decoded_via,
                    "sha256": hashlib.sha256(decoded_bytes).hexdigest(),
                    **self._serialize_text_candidate(
                        decoded_sample,
                        limit=byte_limit,
                        total_bytes=decoded_total,
                        truncated=len(decoded_sample) != decoded_total,
                    ),
                }
            except Exception as exc:
                payload["decoded"] = {
                    "content_encoding": content_encoding,
                    "error": str(exc),
                }

        return payload

    def protocol_path(self, suffix: str) -> str:
        return f"relay/v4/full/{suffix}"

    def delta_init_url(self) -> str:
        return urljoin(f"{self.relay_base_url}/", "relay/v4/delta/init")

    def delta_complete_url(self) -> str:
        return urljoin(f"{self.relay_base_url}/", "relay/v4/delta/complete")

    def refs_init_url(self) -> str:
        return urljoin(f"{self.relay_base_url}/", "relay/v4/refs/init")

    def refs_complete_url(self) -> str:
        return urljoin(f"{self.relay_base_url}/", "relay/v4/refs/complete")

    def delta_chunk_url(self, request_id: str, index: int) -> str:
        return urljoin(f"{self.relay_base_url}/", f"relay/v4/delta/chunks/{request_id}/{index}")

    def refs_chunk_url(self, request_id: str, index: int) -> str:
        return urljoin(f"{self.relay_base_url}/", f"relay/v4/refs/chunks/{request_id}/{index}")

    def encrypted_protocol_enabled(self) -> bool:
        return True

    def aesgcm(self) -> AESGCM:
        return AESGCM(self._encryption_key_bytes)

    def encrypt_bytes(self, plaintext: bytes) -> dict:
        iv = os.urandom(12)
        encrypted = self.aesgcm().encrypt(iv, plaintext, None)
        return {
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": encrypted[:-16],
            "tag": base64.b64encode(encrypted[-16:]).decode("ascii"),
        }

    def decrypt_bytes(self, iv_b64: str, tag_b64: str, ciphertext: bytes) -> bytes:
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        return self.aesgcm().decrypt(iv, ciphertext + tag, None)

    def encode_frame(self, header: dict, payload: bytes) -> bytes:
        header_with_length = {**header, "payloadLength": len(payload)}
        header_json = json.dumps(header_with_length, ensure_ascii=False).encode("utf-8")
        return struct.pack(">I", len(header_json)) + header_json + payload

    def decode_frames(self, payload: bytes) -> list[tuple[dict, bytes]]:
        frames = []
        offset = 0
        while offset < len(payload):
            if offset + 4 > len(payload):
                raise ValueError("invalid encrypted frame prefix")
            (header_length,) = struct.unpack(">I", payload[offset : offset + 4])
            offset += 4
            header_end = offset + header_length
            if header_end > len(payload):
                raise ValueError("invalid encrypted frame header")
            header = json.loads(payload[offset:header_end].decode("utf-8"))
            offset = header_end
            payload_length = int(header.get("payloadLength", 0))
            frame_end = offset + payload_length
            if frame_end > len(payload):
                raise ValueError("invalid encrypted frame payload")
            frames.append((header, payload[offset:frame_end]))
            offset = frame_end
        return frames

    def _print_http_details(self, flow: http.HTTPFlow) -> None:
        if not self.console_log_enabled or not flow.response:
            return
        print("\n" + "🚀" + "=" * 60, flush=True)
        self._log(f"【URL】: {flow.request.pretty_url}")
        self._log(f"【Method】: {flow.request.method}")
        if flow.request.headers.get("upgrade", "").lower() == "websocket":
            self._log("【Upgrade】: websocket")

        self._log("\n--- [Request Headers] ---")
        for k, v in flow.request.headers.items():
            self._log(f"{k}: {self._sanitize_header_value(k, v)}")

        self._log("\n--- [Request Body] ---")
        req_text = flow.request.get_text(strict=False)
        self._pretty_print_text(req_text)

        self._log("\n" + "-" * 40)
        self._log(f"【Status】: {flow.response.status_code}")

        self._log("\n--- [Response Headers] ---")
        for k, v in flow.response.headers.items():
            self._log(f"{k}: {self._sanitize_header_value(k, v)}")

        self._log("\n--- [Response Body] ---")
        try:
            res_text = flow.response.get_text(strict=False)
        except Exception:
            # A streamed response has no buffered body to read back.
            res_text = self.response_body_bytes(flow).decode("utf-8", errors="replace")
        self._pretty_print_text(res_text)

        self._log("=" * 62 + "\n")

    def _print_http_request_details(self, flow: http.HTTPFlow) -> None:
        if not self.console_log_enabled:
            return
        print("\n" + "📥" + "=" * 60, flush=True)
        self._log(f"【HTTP Request Captured】 flow_id={flow.id}")
        self._log(f"【URL】: {flow.request.pretty_url}")
        self._log(f"【Upstream】: {flow.request.host}:{flow.request.port}")
        self._log(f"【Method】: {flow.request.method}")
        self._log("\n--- [Request Headers] ---")
        for k, v in flow.request.headers.items():
            self._log(f"{k}: {self._sanitize_header_value(k, v)}")
        self._log("\n--- [Request Body] ---")
        self._pretty_print_text(flow.request.get_text(strict=False))
        self._log("=" * 62 + "\n")


    def _print_http_route_decision(self, flow: http.HTTPFlow, decision: str, reason: str = "") -> None:
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "http_route_decision",
                "flow_id": flow.id,
                "decision": decision,
                "reason": reason or "",
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "path": flow.request.path.split("?", 1)[0],
                "body_bytes": len(flow.request.raw_content or b""),
                "host_match": self.host_matches(flow.request.host),
                "ws_block_match": self.is_blocked_ws_target(flow),
            },
            flow=flow,
        )
        if not self.console_log_enabled:
            return
        host = (flow.request.host or "").lower()
        path = flow.request.path.split("?", 1)[0]
        body = flow.request.raw_content or b""
        self._log(
            "[HTTP Decision] "
            f"flow_id={flow.id} decision={decision} reason={reason or '-'} "
            f"method={flow.request.method} host={host} path={path} body_bytes={len(body)} "
            f"host_match={self.host_matches(host)} "
            f"ws_block_match={self.is_blocked_ws_target(flow)}"
        )

    def should_record_flow(self, flow: http.HTTPFlow | None) -> bool:
        if flow is None or not flow.request:
            return False
        host = (flow.request.host or "").lower()
        path = flow.request.path.split("?", 1)[0]
        if host == "ab.chatgpt.com" and path == "/otlp/v1/metrics":
            return False
        return self.host_matches(host)

    def append_log(self, payload: dict, *, flow: http.HTTPFlow | None = None, force_file: bool = False) -> None:
        if not force_file and flow is not None and not self.should_record_flow(flow):
            return
        line = f"http_inspect {json.dumps(payload, ensure_ascii=False)}"
        ctx.log.info(line)
        if not self.output_file:
            return
        with Path(self.output_file).expanduser().resolve().open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")

    def append_error_log(self, payload: dict) -> None:
        if not self.error_output_file:
            return
        line = f"http_error_summary {json.dumps(payload, ensure_ascii=False)}"
        with Path(self.error_output_file).expanduser().resolve().open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")

    def maybe_log_error_summary(self, flow: http.HTTPFlow, error: str = "") -> None:
        if not self.error_output_file:
            return
        if flow and flow.request and not self.should_record_flow(flow):
            return
        status_code = flow.response.status_code if flow and flow.response else None
        if not error and status_code is not None and 200 <= status_code < 300:
            return

        request_headers = dict(flow.request.headers) if flow and flow.request else {}
        response_headers = dict(flow.response.headers) if flow and flow.response else {}
        self.append_error_log(
            {
                "ts": self.now_iso(),
                "event": "http_error_summary",
                "flow_id": flow.id if flow else "",
                "method": flow.request.method if flow and flow.request else "",
                "url": flow.request.pretty_url if flow and flow.request else "",
                "host": flow.request.host if flow and flow.request else "",
                "path": flow.request.path if flow and flow.request else "",
                "status_code": status_code,
                "reason": getattr(flow.response, "reason", "") if flow and flow.response else "",
                "error": error,
                "request_headers": self._sanitize_headers(request_headers),
                "request_body": self.serialize_bytes(
                    flow.request.raw_content or b"",
                    request_headers,
                    limit=self.error_body_max_bytes,
                ) if flow and flow.request else self.serialize_bytes(b"", limit=self.error_body_max_bytes),
                "response_headers": self._sanitize_headers(response_headers),
                "response_body": self.serialize_bytes(
                    self.response_body_bytes(flow),
                    response_headers,
                    limit=self.error_body_max_bytes,
                ) if flow and flow.response else self.serialize_bytes(b"", limit=self.error_body_max_bytes),
            }
        )

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def is_relay_self_call(self, flow: http.HTTPFlow) -> bool:
        """
        The relay now lives on the same host the client talks to, so without
        this guard the addon would intercept its own chunk uploads and recurse
        forever.
        """
        if not self.relay_base_url:
            return False
        try:
            _, relay_host, relay_port, relay_path, _ = parse_url(self.relay_base_url)
        except ValueError:
            return False
        if (flow.request.host or "").lower() != (relay_host or "").lower():
            return False
        if flow.request.port != relay_port:
            return False
        prefix = (relay_path or "").rstrip("/") + "/relay/"
        return flow.request.path.split("?", 1)[0].startswith(prefix)

    def is_http_relay_target(self, flow: http.HTTPFlow) -> bool:
        if flow.request.method.upper() != "POST":
            return False
        if self.is_relay_self_call(flow):
            return False
        host = (flow.request.host or "").lower()
        if not self.host_matches(host):
            return False
        return True

    def relay_ready_for_http(self) -> bool:
        return self.enabled and bool(self.relay_base_url)

    def should_intercept(self, flow: http.HTTPFlow) -> bool:
        if not self.relay_ready_for_http():
            return False
        return self.is_http_relay_target(flow)

    def log_intercept_decision(self, flow: http.HTTPFlow) -> None:
        body = flow.request.raw_content or b""
        host = flow.request.host.lower()
        path = flow.request.path.split("?", 1)[0]
        payload = {
            "ts": self.now_iso(),
            "event": "http_relay_decision",
            "method": flow.request.method.upper(),
            "host": host,
            "path": path,
            "body_bytes": len(body),
            "enabled": self.enabled,
            "relay_base_url_set": bool(self.relay_base_url),
            "relay_ready": self.relay_ready_for_http(),
            "host_match": self.host_matches(host),
        }
        self.append_log(payload, flow=flow)
        ctx.log.info(
            "http relay decision "
            f"method={payload['method']} host={payload['host']} path={payload['path']} "
            f"body={payload['body_bytes']} enabled={payload['enabled']} "
            f"relay_base_url={'set' if payload['relay_base_url_set'] else 'empty'} "
            f"relay_ready={payload['relay_ready']} "
            f"host_match={payload['host_match']}"
        )

    def is_blocked_ws_target(self, flow: http.HTTPFlow) -> bool:
        if flow.request.method.upper() != "GET":
            return False
        if self.is_relay_self_call(flow):
            return False
        upgrade = flow.request.headers.get("upgrade", "")
        return upgrade.lower() == "websocket"

    def build_forward_headers(self, flow: http.HTTPFlow) -> dict:
        forwarded = {}
        for key, value in flow.request.headers.items():
            forwarded[key.lower()] = value
        return forwarded

    def build_json_forward_headers(self, flow: http.HTTPFlow) -> dict:
        forwarded = self.build_forward_headers(flow)
        forwarded.pop("content-encoding", None)
        forwarded.pop("content-md5", None)
        return forwarded

    def complete_url(self) -> str:
        return urljoin(f"{self.relay_base_url}/", self.protocol_path("complete"))

    def relay_headers(self) -> dict:
        headers = {"content-type": "application/json"}
        if self.shared_secret:
            headers["x-relay-secret"] = self.shared_secret
        return headers

    def sha256_hex(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def stable_json(self, value) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def canonical_json_hash(self, value) -> str:
        return self.sha256_hex(self.stable_json(value).encode("utf-8"))

    def parse_json_body_object(self, body: bytes) -> dict | None:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    def parse_decoded_json_body_object(self, body: bytes, headers: dict) -> dict | None:
        content_encoding = str(headers.get("content-encoding", "") or headers.get("Content-Encoding", ""))
        try:
            decoded_body, decoded_encoding = self._decode_content_encoding(body, content_encoding)
        except Exception as exc:
            ctx.log.info(
                "chunk relay json parse skipped "
                f"reason=decode_failed content_encoding={content_encoding or 'identity'} error={exc}"
            )
            return None
        body_obj = self.parse_json_body_object(decoded_body)
        if body_obj is not None and decoded_encoding != "identity":
            ctx.log.info(
                "chunk relay decoded request json "
                f"content_encoding={decoded_encoding} raw_bytes={len(body)} decoded_bytes={len(decoded_body)}"
            )
        return body_obj

    def input_item_hashes(self, body_obj: dict) -> list[str]:
        input_items = body_obj.get("input")
        if not isinstance(input_items, list):
            return []
        return [self.canonical_json_hash(item) for item in input_items]

    def collect_string_leaves(self, value, output: list[str]) -> None:
        if isinstance(value, str):
            if len(value) >= self.response_ref_min_chars:
                output.append(value)
            return
        if isinstance(value, list):
            for item in value:
                self.collect_string_leaves(item, output)
            return
        if isinstance(value, dict):
            for item in value.values():
                self.collect_string_leaves(item, output)

    def response_text_candidates(self, body: bytes, headers: dict) -> list[dict]:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return []

        content_type = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
        candidates = []
        if len(text) >= self.response_ref_min_chars:
            candidates.append(text)
        if "json" in content_type:
            try:
                self.collect_string_leaves(json.loads(text), candidates)
            except Exception:
                pass
        if "event-stream" in content_type or "\ndata:" in text:
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped.startswith("data:"):
                    continue
                payload = stripped[5:].strip()
                if not payload or payload == "[DONE]":
                    continue
                try:
                    self.collect_string_leaves(json.loads(payload), candidates)
                except Exception:
                    if len(payload) >= self.response_ref_min_chars:
                        candidates.append(payload)

        output = []
        seen = set()
        for candidate in candidates:
            digest = self.sha256_hex(candidate.encode("utf-8"))
            if digest in seen:
                continue
            seen.add(digest)
            output.append({"sha256": digest, "text": candidate})
        return output

    def apply_response_refs(self, value):
        if isinstance(value, str):
            if len(value) < self.response_ref_min_chars:
                return value, 0
            for snapshot in reversed(self.response_snapshots):
                for candidate in snapshot.get("texts", []):
                    if value == candidate.get("text"):
                        return {
                            "$relayRef": {
                                "type": "responseText",
                                "snapshotId": snapshot["snapshot_id"],
                                "sha256": candidate["sha256"],
                            }
                        }, 1
            return value, 0
        if isinstance(value, list):
            replaced = 0
            output = []
            for item in value:
                next_value, next_count = self.apply_response_refs(item)
                output.append(next_value)
                replaced += next_count
            return output, replaced
        if isinstance(value, dict):
            replaced = 0
            output = {}
            for key, item in value.items():
                next_value, next_count = self.apply_response_refs(item)
                output[key] = next_value
                replaced += next_count
            return output, replaced
        return value, 0

    def target_key(self, flow: http.HTTPFlow) -> str:
        return f"{flow.request.method.upper()} {flow.request.pretty_url}"

    def body_fields_without_input(self, body_obj: dict) -> dict:
        return {key: value for key, value in body_obj.items() if key != "input"}

    def find_delta_snapshot(self, flow: http.HTTPFlow, body_obj: dict) -> dict | None:
        item_hashes = self.input_item_hashes(body_obj)
        if not item_hashes:
            return None
        target_key = self.target_key(flow)
        best = None
        for snapshot in self.delta_snapshots:
            snapshot_hashes = snapshot.get("input_item_hashes") or []
            if snapshot.get("target_key") != target_key:
                continue
            if len(snapshot_hashes) > len(item_hashes):
                continue
            if item_hashes[: len(snapshot_hashes)] != snapshot_hashes:
                continue
            if best is None or len(snapshot_hashes) > len(best.get("input_item_hashes") or []):
                best = snapshot
        return best

    def format_request_error(self, method: str, url: str, exc: Exception) -> str:
        method_upper = (method or "").upper()
        if isinstance(exc, httpx.HTTPStatusError):
            response = exc.response
            location = response.headers.get("Location", "")
            parts = [
                f"relay_request method={method_upper}",
                f"url={url}",
                f"status={response.status_code}",
                f"reason={response.reason_phrase}",
            ]
            response_url = str(response.url)
            if response_url and response_url != url:
                parts.append(f"response_url={response_url}")
            if location:
                parts.append(f"location={location}")
            content_type = response.headers.get("Content-Type", "")
            if content_type:
                parts.append(f"content_type={content_type}")
            response_body = response.content or b""
            if response_body:
                preview = self._bytes_preview(response_body)
                parts.append(f"response_body={json.dumps(preview, ensure_ascii=False)}")
            return " ".join(parts)

        if isinstance(exc, httpx.RequestError):
            return f"relay_request method={method_upper} url={url} error={exc}"

        return f"relay_request method={method_upper} url={url} error={exc}"

    def should_retry_request_error(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.TimeoutException):
            return True
        if isinstance(exc, httpx.NetworkError):
            return True
        if isinstance(exc, httpx.ProtocolError):
            return True
        if isinstance(exc, httpx.ProxyError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in {408, 409, 425, 429, 500, 502, 503, 504}
        return False

    def request_once(self, method: str, url: str, headers=None, content: bytes | None = None) -> dict:
        response = self.http_client.request(
            method,
            url,
            headers=headers or {},
            content=content,
            timeout=self.timeout_seconds,
        )
        try:
            response.read()
            response.raise_for_status()
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.content,
            }
        finally:
            response.close()

    def request_with_retry(self, method: str, url: str, headers=None, content: bytes | None = None, operation: str = ""):
        last_error = None
        last_error_message = ""
        overall_started = time.perf_counter()
        for attempt in range(self.upload_retries + 1):
            attempt_started = time.perf_counter()
            try:
                result = self.request_once(method, url, headers=headers, content=content)
                attempt_elapsed_ms = (time.perf_counter() - attempt_started) * 1000.0
                total_elapsed_ms = (time.perf_counter() - overall_started) * 1000.0
                ctx.log.info(
                    "chunk relay upload attempt succeeded "
                    f"attempt={attempt + 1}/{self.upload_retries + 1} "
                    f"operation={operation or '-'} "
                    f"relay_request method={(method or '').upper()} url={url} "
                    f"status={result['status_code']} "
                    f"attempt_elapsed_ms={attempt_elapsed_ms:.1f} "
                    f"total_elapsed_ms={total_elapsed_ms:.1f}"
                )
                return result
            except httpx.HTTPError as exc:
                last_error = exc
                attempt_elapsed_ms = (time.perf_counter() - attempt_started) * 1000.0
                last_error_message = (
                    f"{self.format_request_error(method, url, exc)} "
                    f"attempt_elapsed_ms={attempt_elapsed_ms:.1f}"
                )
                ctx.log.warn(
                    "chunk relay upload attempt failed "
                    f"attempt={attempt + 1}/{self.upload_retries + 1} "
                    f"operation={operation or '-'} "
                    f"{last_error_message}"
                )
                if attempt >= self.upload_retries or not self.should_retry_request_error(exc):
                    break
                sleep_seconds = (self.retry_backoff_ms * (2 ** attempt)) / 1000.0
                time.sleep(sleep_seconds)
        if last_error_message:
            raise RuntimeError(last_error_message) from last_error
        raise last_error

    def upload_chunks(self, request_id: str, body: bytes, flow: http.HTTPFlow) -> None:
        upload_started = time.perf_counter()
        compressed_body = gzip.compress(body)
        chunk_count = math.ceil(len(compressed_body) / self.chunk_size_bytes)
        headers = self.relay_headers()
        forward_headers = self.build_forward_headers(flow)
        compressed_body_sha256 = self.sha256_hex(compressed_body)
        compression_ratio = (len(compressed_body) / len(body)) if body else 1.0

        if self.encrypted_protocol_enabled():
            metadata_plaintext = {
                "method": flow.request.method.upper(),
                "path": flow.request.path,
                "targetUrl": flow.request.pretty_url,
                "headers": forward_headers,
                "bodySize": len(body),
                "bodySha256": self.sha256_hex(body),
                "relayTransferEncoding": INTERNAL_CONTENT_ENCODING_GZIP,
                "compressedBodySize": len(compressed_body),
                "compressedBodySha256": compressed_body_sha256,
                "chunkCount": chunk_count,
            }
            encrypted_metadata = self.encrypt_bytes(
                json.dumps(metadata_plaintext, ensure_ascii=False).encode("utf-8")
            )
            init_payload = {
                "requestId": request_id,
                "chunkCount": chunk_count,
                "enc": {
                    "alg": AES_256_GCM,
                    "keyId": self.encryption_key_id,
                    "iv": encrypted_metadata["iv"],
                    "tag": encrypted_metadata["tag"],
                    "ciphertext": base64.b64encode(encrypted_metadata["ciphertext"]).decode("ascii"),
                },
            }
            init_payload_for_log = {
                "requestId": request_id,
                "chunkCount": chunk_count,
                "enc": {
                    "alg": AES_256_GCM,
                    "keyId": self.encryption_key_id,
                },
                "metadata": {
                    **metadata_plaintext,
                    "headers": self._sanitize_headers(forward_headers),
                },
            }
        else:
            init_payload = {
                "requestId": request_id,
                "method": flow.request.method.upper(),
                "path": flow.request.path,
                "targetUrl": flow.request.pretty_url,
                "headers": forward_headers,
                "bodySize": len(body),
                "bodySha256": self.sha256_hex(body),
                "relayTransferEncoding": INTERNAL_CONTENT_ENCODING_GZIP,
                "compressedBodySize": len(compressed_body),
                "compressedBodySha256": compressed_body_sha256,
                "chunkCount": chunk_count,
            }
            init_payload_for_log = {
                **init_payload,
                "headers": self._sanitize_headers(forward_headers),
            }
        ctx.log.info(
            "chunk relay init payload "
            f"request_id={request_id} "
            f"body_bytes_before_compress={len(body)} "
            f"body_bytes_after_compress={len(compressed_body)} "
            f"compression_ratio={compression_ratio:.3f} "
            f"payload={json.dumps(init_payload_for_log, ensure_ascii=False)}"
        )
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "chunk_relay_init_payload",
                "request_id": request_id,
                "payload": init_payload_for_log,
            },
            force_file=True,
        )

        self.request_with_retry(
            "POST",
            urljoin(f"{self.relay_base_url}/", self.protocol_path("init")),
            headers=headers,
            content=json.dumps(init_payload, ensure_ascii=False).encode("utf-8"),
            operation=f"init request_id={request_id}",
        )

        for index in range(chunk_count):
            start = index * self.chunk_size_bytes
            end = start + self.chunk_size_bytes
            chunk = compressed_body[start:end]
            chunk_headers = {}
            if self.shared_secret:
                chunk_headers["x-relay-secret"] = self.shared_secret
            chunk_headers["content-type"] = "application/octet-stream"
            if self.encrypted_protocol_enabled():
                encrypted_chunk = self.encrypt_bytes(chunk)
                chunk_payload = encrypted_chunk["ciphertext"]
                chunk_headers["x-chunk-iv"] = encrypted_chunk["iv"]
                chunk_headers["x-chunk-tag"] = encrypted_chunk["tag"]
            else:
                chunk_payload = chunk
            chunk_headers["x-chunk-size"] = str(len(chunk_payload))
            chunk_headers["x-chunk-sha256"] = self.sha256_hex(chunk_payload)
            self.request_with_retry(
                "PUT",
                urljoin(f"{self.relay_base_url}/", f"{self.protocol_path('chunks')}/{request_id}/{index}"),
                headers=chunk_headers,
                content=chunk_payload,
                operation=f"chunk request_id={request_id} index={index} bytes={len(chunk_payload)}",
            )
        total_elapsed_ms = (time.perf_counter() - upload_started) * 1000.0
        ctx.log.info(
            "chunk relay upload finished "
            f"request_id={request_id} chunks={chunk_count} "
            f"body_bytes_before_compress={len(body)} body_bytes_after_compress={len(compressed_body)} "
            f"compression_ratio={compression_ratio:.3f} total_elapsed_ms={total_elapsed_ms:.1f}"
        )

    def upload_encrypted_json_chunks(
        self,
        *,
        request_id: str,
        payload_bytes: bytes,
        init_url: str,
        chunk_url_factory,
        payload_version: str,
        operation_label: str,
    ) -> bool:
        upload_started = time.perf_counter()
        compressed_payload = gzip.compress(payload_bytes)
        chunk_count = math.ceil(len(compressed_payload) / self.chunk_size_bytes)
        compressed_payload_sha256 = self.sha256_hex(compressed_payload)
        metadata_plaintext = {
            "version": payload_version,
            "relayTransferEncoding": INTERNAL_CONTENT_ENCODING_GZIP,
            "bodySize": len(payload_bytes),
            "bodySha256": self.sha256_hex(payload_bytes),
            "compressedBodySize": len(compressed_payload),
            "compressedBodySha256": compressed_payload_sha256,
            "chunkCount": chunk_count,
        }
        encrypted_metadata = self.encrypt_bytes(json.dumps(metadata_plaintext, ensure_ascii=False).encode("utf-8"))
        init_payload = {
            "requestId": request_id,
            "chunkCount": chunk_count,
            "enc": {
                "alg": AES_256_GCM,
                "keyId": self.encryption_key_id,
                "iv": encrypted_metadata["iv"],
                "tag": encrypted_metadata["tag"],
                "ciphertext": base64.b64encode(encrypted_metadata["ciphertext"]).decode("ascii"),
            },
        }

        self.request_with_retry(
            "POST",
            init_url,
            headers=self.relay_headers(),
            content=json.dumps(init_payload, ensure_ascii=False).encode("utf-8"),
            operation=f"{operation_label} chunked init request_id={request_id} chunks={chunk_count}",
        )

        for index in range(chunk_count):
            start = index * self.chunk_size_bytes
            end = start + self.chunk_size_bytes
            chunk = compressed_payload[start:end]
            encrypted_chunk = self.encrypt_bytes(chunk)
            chunk_payload = encrypted_chunk["ciphertext"]
            chunk_headers = {
                "content-type": "application/octet-stream",
                "x-chunk-iv": encrypted_chunk["iv"],
                "x-chunk-tag": encrypted_chunk["tag"],
                "x-chunk-size": str(len(chunk_payload)),
                "x-chunk-sha256": self.sha256_hex(chunk_payload),
            }
            if self.shared_secret:
                chunk_headers["x-relay-secret"] = self.shared_secret
            self.request_with_retry(
                "PUT",
                chunk_url_factory(request_id, index),
                headers=chunk_headers,
                content=chunk_payload,
                operation=f"{operation_label} chunk request_id={request_id} index={index} bytes={len(chunk_payload)}",
            )

        total_elapsed_ms = (time.perf_counter() - upload_started) * 1000.0
        ctx.log.info(
            "chunk relay encrypted json chunks uploaded "
            f"request_id={request_id} operation={operation_label} chunks={chunk_count} "
            f"payload_bytes={len(payload_bytes)} compressed_bytes={len(compressed_payload)} "
            f"total_elapsed_ms={total_elapsed_ms:.1f}"
        )
        return True

    def upload_delta(self, request_id: str, body_obj: dict, body_template: dict, flow: http.HTTPFlow) -> bool:
        snapshot = self.find_delta_snapshot(flow, body_obj)
        if not snapshot:
            return False

        item_hashes = self.input_item_hashes(body_obj)
        base_count = len(snapshot.get("input_item_hashes") or [])
        delta_payload = {
            "requestId": request_id,
            "method": flow.request.method.upper(),
            "path": flow.request.path,
            "targetUrl": flow.request.pretty_url,
            "headers": self.build_json_forward_headers(flow),
            "baseSnapshotId": snapshot["snapshot_id"],
            "baseBodySha256": snapshot["body_sha256"],
            "patchType": "responses-input-tail-v1",
            "baseInputItemCount": base_count,
            "appendInputItems": body_template.get("input", [])[base_count:],
            "bodyFields": self.body_fields_without_input(body_template),
            "canonicalBodySha256": self.canonical_json_hash(body_obj),
        }
        payload_bytes = json.dumps(delta_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ctx.log.info(
            "chunk relay delta uploading encrypted chunks "
            f"request_id={request_id} base_snapshot={snapshot['snapshot_id']} "
            f"base_items={base_count} total_items={len(item_hashes)} delta_bytes={len(payload_bytes)}"
        )
        try:
            return self.upload_encrypted_json_chunks(
                request_id=request_id,
                payload_bytes=payload_bytes,
                init_url=self.delta_init_url(),
                chunk_url_factory=self.delta_chunk_url,
                payload_version="v4-delta-chunked",
                operation_label="delta",
            )
        except Exception as exc:
            raise NonFallbackRelayError(f"delta encrypted chunk upload failed: {exc}") from exc

    def upload_refs(self, request_id: str, body_obj: dict, body_template: dict, flow: http.HTTPFlow) -> bool:
        delta_payload = {
            "requestId": request_id,
            "method": flow.request.method.upper(),
            "path": flow.request.path,
            "targetUrl": flow.request.pretty_url,
            "headers": self.build_json_forward_headers(flow),
            "bodyTemplate": body_template,
            "canonicalBodySha256": self.canonical_json_hash(body_obj),
        }
        payload_bytes = json.dumps(delta_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ctx.log.info(
            f"chunk relay refs uploading encrypted chunks request_id={request_id} refs_bytes={len(payload_bytes)}"
        )
        try:
            return self.upload_encrypted_json_chunks(
                request_id=request_id,
                payload_bytes=payload_bytes,
                init_url=self.refs_init_url(),
                chunk_url_factory=self.refs_chunk_url,
                payload_version="v4-refs-chunked",
                operation_label="refs",
            )
        except Exception as exc:
            raise NonFallbackRelayError(f"refs encrypted chunk upload failed: {exc}") from exc

    def rewrite_flow(self, flow: http.HTTPFlow, request_id: str, complete_url: str | None = None) -> None:
        url = complete_url or self.complete_url()
        scheme, host, port, path, query = require_url("CHUNK_RELAY_BASE_URL", url, {"http", "https"})
        flow.request.scheme = scheme
        flow.request.host = host
        flow.request.port = port
        flow.request.path = f"{path}?{query}" if query else path
        flow.request.method = "POST"
        flow.request.headers.clear()
        flow.request.headers["host"] = format_host_header(host, port, scheme)
        flow.request.headers["content-type"] = "application/json"
        flow.request.headers["accept"] = "text/event-stream"
        if self.shared_secret:
            flow.request.headers["x-relay-secret"] = self.shared_secret
        flow.request.text = json.dumps({"requestId": request_id}, ensure_ascii=False)
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "http_relay_rewrite",
                "request_id": request_id,
                "url": flow.request.pretty_url,
                "upstream_host": flow.request.host,
                "upstream_port": flow.request.port,
                "method": flow.request.method,
                "path": flow.request.path,
                "headers": self._sanitize_headers(dict(flow.request.headers)),
                "body_bytes": len(flow.request.raw_content or b""),
            },
            flow=flow,
            force_file=True,
        )

    def block_websocket_flow(self, flow: http.HTTPFlow) -> None:
        # The relay has no WebSocket transport, so the client must fall back to
        # HTTPS. 503 reads as "try again later" and costs the Codex CLI five
        # reconnect attempts; 501 says the upgrade will never work.
        flow.response = http.Response.make(
            self.ws_block_status,
            b"WebSocket relay disabled; please use HTTP fallback.",
            {"content-type": "text/plain; charset=utf-8"},
        )
        self._print_http_route_decision(flow, "ws_blocked", "websocket_disabled")

    def block_unavailable_http_relay(self, flow: http.HTTPFlow) -> None:
        flow.response = http.Response.make(
            503,
            b"HTTP relay unavailable; direct upstream is disabled.",
            {"content-type": "text/plain; charset=utf-8"},
        )
        self.log_intercept_decision(flow)
        self._print_http_route_decision(flow, "blocked", "relay_unavailable_direct_disabled")

    def pass_through_flow(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() == "POST" and not self.is_relay_self_call(flow):
            if self.host_matches(flow.request.host):
                self.log_intercept_decision(flow)
        self._print_http_route_decision(flow, "pass_through", "not_intercepted")

    def relay_http_flow(self, flow: http.HTTPFlow) -> None:
        body = flow.request.raw_content or b""
        request_id = uuid.uuid4().hex
        body_obj = self.parse_decoded_json_body_object(body, dict(flow.request.headers))
        body_template = body_obj
        response_ref_count = 0
        used_delta = False
        used_refs = False
        try:
            self.log_intercept_decision(flow)
            ctx.log.info(
                f"chunk relay intercepting {flow.request.pretty_url} "
                f"body={len(body)} request_id={request_id}"
            )
            if body_obj is not None:
                body_template, response_ref_count = self.apply_response_refs(body_obj)
                try:
                    used_delta = self.upload_delta(request_id, body_obj, body_template, flow)
                except NonFallbackRelayError:
                    raise
                except Exception as exc:
                    ctx.log.warn(f"chunk relay delta failed, falling back to full chunks: {exc}")

            if used_delta:
                self.pending_snapshots[request_id] = {
                    "target_key": self.target_key(flow),
                    "target_url": flow.request.pretty_url,
                    "body_sha256": self.canonical_json_hash(body_obj),
                    "input_item_hashes": self.input_item_hashes(body_obj),
                }
                self.rewrite_flow(flow, request_id, self.delta_complete_url())
                self._print_http_route_decision(flow, "delta_rewrite", f"request_id={request_id}")
            elif body_obj is not None and response_ref_count > 0:
                try:
                    used_refs = self.upload_refs(request_id, body_obj, body_template, flow)
                except NonFallbackRelayError:
                    raise
                except Exception as exc:
                    ctx.log.warn(f"chunk relay refs failed, falling back to full chunks: {exc}")
                if used_refs:
                    self.pending_snapshots[request_id] = {
                        "target_key": self.target_key(flow),
                        "target_url": flow.request.pretty_url,
                        "body_sha256": self.canonical_json_hash(body_obj),
                        "input_item_hashes": self.input_item_hashes(body_obj),
                    }
                    self.rewrite_flow(flow, request_id, self.refs_complete_url())
                    self._print_http_route_decision(
                        flow,
                        "refs_rewrite",
                        f"request_id={request_id} response_refs={response_ref_count}",
                    )
                else:
                    self.upload_chunks(request_id, body, flow)
                    self.pending_snapshots[request_id] = {
                        "target_key": self.target_key(flow),
                        "target_url": flow.request.pretty_url,
                        "body_sha256": self.canonical_json_hash(body_obj),
                        "input_item_hashes": self.input_item_hashes(body_obj),
                    }
                    self.rewrite_flow(flow, request_id)
                    self._print_http_route_decision(flow, "chunk_rewrite", f"request_id={request_id}")
            else:
                self.upload_chunks(request_id, body, flow)
                if body_obj is not None:
                    self.pending_snapshots[request_id] = {
                        "target_key": self.target_key(flow),
                        "target_url": flow.request.pretty_url,
                        "body_sha256": self.canonical_json_hash(body_obj),
                        "input_item_hashes": self.input_item_hashes(body_obj),
                    }
                self.rewrite_flow(flow, request_id)
                self._print_http_route_decision(flow, "chunk_rewrite", f"request_id={request_id}")
        except Exception as exc:
            ctx.log.error(f"chunk relay failed: {exc}")
            self._log("\n" + "❌" + "=" * 60)
            self._log("【Chunk Relay Error】")
            self._log(f"url={flow.request.pretty_url}")
            self._log(f"error={exc}")
            self._log("=" * 62 + "\n")
            self._print_http_route_decision(flow, "error", "chunk_relay_failed")
            flow.response = http.Response.make(
                502,
                json.dumps(
                    {
                        "error": {
                            "message": f"chunk relay failed: {exc}"
                        }
                    },
                    ensure_ascii=False,
                ).encode("utf-8"),
                {"content-type": "application/json; charset=utf-8"},
            )

    def log_http_request(self, flow: http.HTTPFlow) -> None:
        self._print_http_request_details(flow)
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "http_request",
                "flow_id": flow.id,
                "method": flow.request.method,
                "scheme": flow.request.scheme,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "http_version": flow.request.http_version,
                "headers": self._sanitize_headers(dict(flow.request.headers)),
                "body": self.serialize_bytes(flow.request.raw_content or b"", dict(flow.request.headers)),
            },
            flow=flow,
        )

    def handle_request_flow(self, flow: http.HTTPFlow) -> None:
        host = (flow.request.host or "").lower()
        if not self.host_matches(host):
            self.pass_through_flow(flow)
            return

        if self.is_blocked_ws_target(flow):
            self.block_websocket_flow(flow)
            return

        if not self.should_intercept(flow):
            self.pass_through_flow(flow)
            return

        self.relay_http_flow(flow)

    def request(self, flow: http.HTTPFlow) -> None:
        self.log_http_request(flow)
        self.handle_request_flow(flow)

    def response_body_bytes(self, flow: http.HTTPFlow) -> bytes:
        """Response body, safe to call on a streamed (decrypted) response."""
        if not flow.response:
            return b""
        if flow.metadata.get("relay_response_streaming"):
            return flow.metadata.get("relay_response_plaintext") or b""
        try:
            return flow.response.raw_content or b""
        except Exception:
            return b""

    def make_response_decryptor(self, flow: http.HTTPFlow):
        """
        Returns a mitmproxy streaming callback that decrypts relay response
        frames as they arrive. Buffering the whole response instead would stall
        SSE until the model finished generating, which the Codex CLI reads as a
        dead connection and retries.
        """
        state = {"buffer": bytearray(), "plaintext": bytearray()}

        def decrypt_stream(data: bytes) -> list[bytes]:
            # Must return a LIST, not bytes: with transfer-encoding chunked,
            # returning b"" makes mitmproxy emit the terminating 0-length chunk
            # and the response ends mid-stream. An empty list emits nothing.
            try:
                return decrypt_chunk(data)
            except Exception as exc:
                ctx.log.error(f"relay response decryption failed: {exc!r}")
                raise

        def decrypt_chunk(data: bytes) -> list[bytes]:
            if data:
                state["buffer"].extend(data)

            out = bytearray()
            buffer = state["buffer"]
            offset = 0
            while True:
                if len(buffer) - offset < 4:
                    break
                header_length = int.from_bytes(buffer[offset : offset + 4], "big")
                header_start = offset + 4
                header_end = header_start + header_length
                if len(buffer) < header_end:
                    break
                try:
                    header = json.loads(bytes(buffer[header_start:header_end]).decode("utf-8"))
                except Exception as exc:
                    raise ValueError(f"invalid relay response frame header: {exc}") from exc
                payload_length = int(header.get("payloadLength", 0))
                frame_end = header_end + payload_length
                if len(buffer) < frame_end:
                    break

                ciphertext = bytes(buffer[header_end:frame_end])
                offset = frame_end
                frame_type = header.get("type")
                if frame_type == "meta":
                    # Status and headers already went out as clear headers so we
                    # could start streaming; nothing left to apply here.
                    continue
                if frame_type != "data":
                    raise ValueError(f"unexpected response frame type: {frame_type}")
                plaintext = self.decrypt_bytes(header["iv"], header["tag"], ciphertext)
                out.extend(plaintext)

            if offset:
                del buffer[:offset]

            state["plaintext"].extend(out)

            if not data:
                if buffer:
                    raise ValueError("truncated encrypted relay response")
                flow.metadata["relay_response_plaintext"] = bytes(state["plaintext"])

            return [bytes(out)] if out else []

        return decrypt_stream

    def maybe_stream_decrypt_response(self, flow: http.HTTPFlow) -> None:
        """Installed from the responseheaders hook, before any body arrives."""
        if not flow.response:
            return
        if flow.response.headers.get(RESPONSE_ENCRYPTED_HEADER, "") != RESPONSE_FRAME_PROTOCOL:
            return

        status = flow.response.headers.get(UPSTREAM_STATUS_HEADER, "")
        content_type = flow.response.headers.get(UPSTREAM_CONTENT_TYPE_HEADER, "")
        if not status:
            # No streaming preamble: fall back to whole-body decryption.
            return

        try:
            flow.response.status_code = int(status)
        except ValueError:
            return

        flow.response.headers.pop("content-length", None)
        flow.response.headers.pop(UPSTREAM_STATUS_HEADER, None)
        flow.response.headers.pop(UPSTREAM_CONTENT_TYPE_HEADER, None)
        flow.response.headers.pop(RESPONSE_ENCRYPTED_HEADER, None)
        if content_type:
            flow.response.headers["content-type"] = content_type

        flow.metadata["relay_response_streaming"] = True
        flow.response.stream = self.make_response_decryptor(flow)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        try:
            self.maybe_stream_decrypt_response(flow)
        except Exception as exc:
            ctx.log.error(f"relay response stream setup failed: {exc}")

    def maybe_decrypt_v2_response(self, flow: http.HTTPFlow) -> None:
        if not self.encrypted_protocol_enabled():
            return
        if not flow.response:
            return
        if flow.metadata.get("relay_response_streaming"):
            return
        if flow.response.headers.get("x-relay-response-encrypted", "") != RESPONSE_FRAME_PROTOCOL:
            return

        raw = flow.response.raw_content or b""
        frames = self.decode_frames(raw)
        if not frames:
            raise ValueError("empty encrypted relay response")

        status_code = flow.response.status_code
        restored_headers = {}
        plaintext_chunks = []
        for header, ciphertext in frames:
            plaintext = self.decrypt_bytes(header["iv"], header["tag"], ciphertext)
            if header.get("type") == "meta":
                metadata = json.loads(plaintext.decode("utf-8"))
                status_code = int(metadata.get("status", status_code))
                restored_headers = dict(metadata.get("headers", {}))
                continue
            if header.get("type") != "data":
                raise ValueError(f"unexpected response frame type: {header.get('type')}")
            plaintext_chunks.append(plaintext)

        flow.response.status_code = status_code
        flow.response.headers.clear()
        for key, value in restored_headers.items():
            if key.lower() == "content-length":
                continue
            flow.response.headers[key] = value
        flow.response.content = b"".join(plaintext_chunks)

    def relay_request_id_from_rewritten_flow(self, flow: http.HTTPFlow) -> str:
        try:
            payload = json.loads((flow.request.raw_content or b"{}").decode("utf-8"))
        except Exception:
            return ""
        value = payload.get("requestId") if isinstance(payload, dict) else ""
        return value if isinstance(value, str) else ""

    def maybe_record_delta_snapshot(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        snapshot_id = flow.response.headers.get("x-relay-snapshot-id", "")
        snapshot_body_sha256 = flow.response.headers.get("x-relay-snapshot-body-sha256", "")
        if not snapshot_id or not snapshot_body_sha256:
            return

        request_id = self.relay_request_id_from_rewritten_flow(flow)
        pending = self.pending_snapshots.pop(request_id, None)
        if not pending:
            return
        if flow.response.status_code < 200 or flow.response.status_code >= 300:
            return

        snapshot = {
            "snapshot_id": snapshot_id,
            "body_sha256": snapshot_body_sha256,
            "target_key": pending["target_key"],
            "target_url": pending["target_url"],
            "input_item_hashes": pending["input_item_hashes"],
            "created_at": self.now_iso(),
        }
        self.delta_snapshots.append(snapshot)
        if len(self.delta_snapshots) > self.max_delta_snapshots:
            self.delta_snapshots = self.delta_snapshots[-self.max_delta_snapshots :]
        ctx.log.info(
            "chunk relay snapshot recorded "
            f"request_id={request_id} snapshot_id={snapshot_id} "
            f"items={len(snapshot['input_item_hashes'])} target={snapshot['target_url']}"
        )

        for header_name in (
            "x-relay-snapshot-id",
            "x-relay-snapshot-body-sha256",
            "x-relay-snapshot-input-count",
        ):
            if header_name in flow.response.headers:
                del flow.response.headers[header_name]

    def maybe_record_response_snapshot(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        response_snapshot_id = flow.response.headers.get("x-relay-response-snapshot-id", "")
        if not response_snapshot_id:
            return
        if flow.response.status_code < 200 or flow.response.status_code >= 300:
            return
        texts = self.response_text_candidates(
            self.response_body_bytes(flow),
            dict(flow.response.headers),
        )
        if texts:
            self.response_snapshots.append({
                "snapshot_id": response_snapshot_id,
                "texts": texts,
                "created_at": self.now_iso(),
            })
            if len(self.response_snapshots) > self.max_response_snapshots:
                self.response_snapshots = self.response_snapshots[-self.max_response_snapshots :]
            ctx.log.info(
                "chunk relay response snapshot recorded "
                f"snapshot_id={response_snapshot_id} texts={len(texts)}"
            )
        if "x-relay-response-snapshot-id" in flow.response.headers:
            del flow.response.headers["x-relay-response-snapshot-id"]

    def response(self, flow: http.HTTPFlow) -> None:
        self.maybe_decrypt_v2_response(flow)
        self.maybe_record_delta_snapshot(flow)
        self.maybe_record_response_snapshot(flow)
        self.maybe_log_error_summary(flow)
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "http_response",
                "flow_id": flow.id,
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status_code": flow.response.status_code if flow.response else None,
                "reason": getattr(flow.response, "reason", "") if flow.response else "",
                "http_version": getattr(flow.response, "http_version", "") if flow.response else "",
                "headers": self._sanitize_headers(dict(flow.response.headers)) if flow.response else {},
                "body": self.serialize_bytes(self.response_body_bytes(flow), dict(flow.response.headers)) if flow.response else self.serialize_bytes(b""),
            },
            flow=flow,
        )
        self._print_http_details(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        err = str(flow.error) if flow.error else "unknown"
        self.maybe_log_error_summary(flow, err)
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "http_error",
                "flow_id": flow.id,
                "url": flow.request.pretty_url if flow.request else "",
                "method": flow.request.method if flow.request else "",
                "host": flow.request.host if flow.request else "",
                "path": flow.request.path if flow.request else "",
                "headers": self._sanitize_headers(dict(flow.request.headers)) if flow.request else {},
                "body": self.serialize_bytes(flow.request.raw_content or b"", dict(flow.request.headers)) if flow.request else self.serialize_bytes(b""),
                "error": err,
            },
            flow=flow,
        )

        if self.console_log_enabled:
            print("\n" + "💥" + "=" * 60, flush=True)
            self._log("【HTTP Flow Error】")
            if flow.request:
                self._log(f"【URL】: {flow.request.pretty_url}")
                self._log(f"【Method】: {flow.request.method}")
                self._log("\n--- [Request Headers] ---")
                for k, v in flow.request.headers.items():
                    self._log(f"{k}: {self._sanitize_header_value(k, v)}")
                self._log("\n--- [Request Body] ---")
                self._pretty_print_text(flow.request.get_text(strict=False))
            self._log("\n--- [Error] ---")
            self._log(err)
            self._log("=" * 62 + "\n")

addons = [CodexChunkRelayAddon()]
