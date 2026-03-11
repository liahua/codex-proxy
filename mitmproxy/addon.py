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
from datetime import datetime, timezone

from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from mitmproxy import ctx, http

REDACTED_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-relay-secret",
}

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
    path = parsed.path or "/"
    query = parsed.query
    return scheme, host, port, path, query


def format_host_header(host: str, port: int | None) -> str:
    if not host:
        return host
    host_value = host
    if ":" in host and not host.startswith("["):
        host_value = f"[{host}]"
    if port is None:
        return host_value
    return f"{host_value}:{port}"


def require_explicit_url(env_name: str, url: str, allowed_schemes: set[str]) -> tuple[str, str, int, str, str]:
    scheme, host, port, path, query = parse_url(url)
    if not scheme:
        raise ValueError(f"{env_name} must include URL scheme")
    if scheme not in allowed_schemes:
        raise ValueError(f"{env_name} scheme must be one of {sorted(allowed_schemes)}, got {scheme}")
    if not host:
        raise ValueError(f"{env_name} must include host")
    if port is None:
        raise ValueError(f"{env_name} must include an explicit port")
    return scheme, host, port, path, query


def http_request(method: str, url: str, headers=None, body: bytes | None = None, timeout: int = 120):
    req = Request(url=url, data=body, headers=headers or {}, method=method)
    return urlopen(req, timeout=timeout)


class CodexChunkRelayAddon:
    def __init__(self):
        self.enabled = env_bool("CHUNK_RELAY_ENABLED", True)
        self.relay_base_url = os.getenv("CHUNK_RELAY_BASE_URL", "").rstrip("/")
        self.shared_secret = os.getenv("CHUNK_RELAY_SHARED_SECRET", "")
        self.chunk_size_bytes = env_int("CHUNK_RELAY_CHUNK_SIZE_BYTES", 20 * 1024)
        self.timeout_seconds = env_int("CHUNK_RELAY_TIMEOUT_SECONDS", 600)
        self.upload_retries = env_int("CHUNK_RELAY_UPLOAD_RETRIES", 3)
        self.retry_backoff_ms = env_int("CHUNK_RELAY_RETRY_BACKOFF_MS", 400)
        self.match_hosts = {
            item.strip().lower()
            for item in os.getenv("CHUNK_RELAY_MATCH_HOSTS", "127.0.0.1,localhost,chatgpt.com,ab.chatgpt.com").split(",")
            if item.strip()
        }
        self.console_log_enabled = env_bool("CHUNK_RELAY_CONSOLE_LOG", True)

        if self.relay_base_url:
            require_explicit_url("CHUNK_RELAY_BASE_URL", self.relay_base_url, {"http", "https"})

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
        ctx.log.info(
            "chunk relay addon loaded: "
            f"enabled={self.enabled}, relay_base_url={self.relay_base_url or '<empty>'}, "
            f"http_always_relay_matched=true, chunk_size={self.chunk_size_bytes}, "
            f"matched_hosts={sorted(self.match_hosts)}, ws_policy=block_503, "
            f"console_log={self.console_log_enabled}"
        )

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

    def _sanitize_headers(self, headers: dict) -> dict:
        sanitized = {}
        for key, value in (headers or {}).items():
            if not isinstance(value, str):
                continue
            lowered = key.lower()
            sanitized[lowered] = "<redacted>" if lowered in REDACTED_HEADER_KEYS else value
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
            self._log(f"{k}: {v}")

        self._log("\n--- [Request Body] ---")
        req_text = flow.request.get_text(strict=False)
        self._pretty_print_text(req_text)

        self._log("\n" + "-" * 40)
        self._log(f"【Status】: {flow.response.status_code}")

        self._log("\n--- [Response Headers] ---")
        for k, v in flow.response.headers.items():
            self._log(f"{k}: {v}")

        self._log("\n--- [Response Body] ---")
        res_text = flow.response.get_text(strict=False)
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
            self._log(f"{k}: {v}")
        self._log("\n--- [Request Body] ---")
        self._pretty_print_text(flow.request.get_text(strict=False))
        self._log("=" * 62 + "\n")


    def _print_http_route_decision(self, flow: http.HTTPFlow, decision: str, reason: str = "") -> None:
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

    def append_log(self, payload: dict) -> None:
        ctx.log.info(f"http_inspect {json.dumps(payload, ensure_ascii=False)}")

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def is_http_relay_target(self, flow: http.HTTPFlow) -> bool:
        if flow.request.method.upper() != "POST":
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
        self.append_log(payload)
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
        if not self.host_matches(flow.request.host):
            return False
        upgrade = flow.request.headers.get("upgrade", "")
        return upgrade.lower() == "websocket"

    def build_forward_headers(self, flow: http.HTTPFlow) -> dict:
        forwarded = {}
        for key, value in flow.request.headers.items():
            forwarded[key.lower()] = value
        return forwarded

    def complete_url(self) -> str:
        return urljoin(f"{self.relay_base_url}/", "relay/v1/chunked/complete")

    def relay_headers(self) -> dict:
        headers = {"content-type": "application/json"}
        if self.shared_secret:
            headers["x-relay-secret"] = self.shared_secret
        return headers

    def sha256_hex(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def format_request_error(self, method: str, url: str, exc: Exception) -> str:
        method_upper = (method or "").upper()
        if isinstance(exc, HTTPError):
            location = ""
            if exc.headers:
                location = exc.headers.get("Location", "")
            parts = [
                f"relay_request method={method_upper}",
                f"url={url}",
                f"status={exc.code}",
                f"reason={exc.reason}",
            ]
            response_url = exc.geturl() if hasattr(exc, "geturl") else ""
            if response_url and response_url != url:
                parts.append(f"response_url={response_url}")
            if location:
                parts.append(f"location={location}")
            content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
            if content_type:
                parts.append(f"content_type={content_type}")
            try:
                response_body = exc.read() if hasattr(exc, "read") else b""
            except Exception:
                response_body = b""
            if response_body:
                preview = self._bytes_preview(response_body)
                parts.append(f"response_body={json.dumps(preview, ensure_ascii=False)}")
            return " ".join(parts)

        if isinstance(exc, URLError):
            return f"relay_request method={method_upper} url={url} error={exc.reason}"

        return f"relay_request method={method_upper} url={url} error={exc}"

    def request_with_retry(self, method: str, url: str, headers=None, content: bytes | None = None):
        last_error = None
        last_error_message = ""
        for attempt in range(self.upload_retries + 1):
            try:
                response = http_request(method, url, headers=headers or {}, body=content, timeout=self.timeout_seconds)
                return response
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                last_error = exc
                last_error_message = self.format_request_error(method, url, exc)
                ctx.log.warn(
                    "chunk relay upload attempt failed "
                    f"attempt={attempt + 1}/{self.upload_retries + 1} "
                    f"{last_error_message}"
                )
                if attempt >= self.upload_retries:
                    break
                sleep_seconds = (self.retry_backoff_ms * (2 ** attempt)) / 1000.0
                time.sleep(sleep_seconds)
        if last_error_message:
            raise RuntimeError(last_error_message) from last_error
        raise last_error

    def upload_chunks(self, request_id: str, body: bytes, flow: http.HTTPFlow) -> None:
        chunk_count = math.ceil(len(body) / self.chunk_size_bytes)
        headers = self.relay_headers()
        forward_headers = self.build_forward_headers(flow)

        init_payload = {
            "requestId": request_id,
            "method": flow.request.method.upper(),
            "path": flow.request.path,
            "targetUrl": flow.request.pretty_url,
            "headers": forward_headers,
            "bodySize": len(body),
            "bodySha256": self.sha256_hex(body),
            "chunkCount": chunk_count,
        }

        init_payload_for_log = {
            **init_payload,
            "headers": self._sanitize_headers(forward_headers),
        }
        ctx.log.info(
            "chunk relay init payload "
            f"request_id={request_id} "
            f"payload={json.dumps(init_payload_for_log, ensure_ascii=False)}"
        )
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "chunk_relay_init_payload",
                "request_id": request_id,
                "payload": init_payload_for_log,
            },
        )

        self.request_with_retry(
            "POST",
            urljoin(f"{self.relay_base_url}/", "relay/v1/chunked/init"),
            headers=headers,
            content=json.dumps(init_payload, ensure_ascii=False).encode("utf-8"),
        )

        for index in range(chunk_count):
            start = index * self.chunk_size_bytes
            end = start + self.chunk_size_bytes
            chunk = body[start:end]
            chunk_headers = {}
            if self.shared_secret:
                chunk_headers["x-relay-secret"] = self.shared_secret
            chunk_headers["content-type"] = "application/octet-stream"
            chunk_headers["x-chunk-size"] = str(len(chunk))
            chunk_headers["x-chunk-sha256"] = self.sha256_hex(chunk)
            self.request_with_retry(
                "PUT",
                urljoin(f"{self.relay_base_url}/", f"relay/v1/chunked/chunks/{request_id}/{index}"),
                headers=chunk_headers,
                content=chunk,
            )

    def rewrite_flow(self, flow: http.HTTPFlow, request_id: str) -> None:
        url = self.complete_url()
        scheme, host, port, path, query = require_explicit_url("CHUNK_RELAY_BASE_URL", url, {"http", "https"})
        flow.request.scheme = scheme
        flow.request.host = host
        flow.request.port = port
        flow.request.path = f"{path}?{query}" if query else path
        flow.request.method = "POST"
        flow.request.headers.clear()
        flow.request.headers["host"] = format_host_header(host, port)
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
                "headers": dict(flow.request.headers),
                "body_bytes": len(flow.request.raw_content or b""),
            },
        )

    def block_websocket_flow(self, flow: http.HTTPFlow) -> None:
        flow.response = http.Response.make(
            503,
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
        if flow.request.method.upper() == "POST":
            if self.host_matches(flow.request.host):
                self.log_intercept_decision(flow)
        self._print_http_route_decision(flow, "pass_through", "not_intercepted")

    def relay_http_flow(self, flow: http.HTTPFlow) -> None:
        body = flow.request.raw_content or b""
        request_id = uuid.uuid4().hex
        try:
            self.log_intercept_decision(flow)
            ctx.log.info(
                f"chunk relay intercepting {flow.request.pretty_url} "
                f"body={len(body)} request_id={request_id}"
            )
            self.upload_chunks(request_id, body, flow)
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
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "body_bytes": len(flow.request.raw_content or b""),
            },
        )

    def handle_request_flow(self, flow: http.HTTPFlow) -> None:
        host = (flow.request.host or "").lower()
        if not self.host_matches(host):
            self.pass_through_flow(flow)
            return

        if self.is_blocked_ws_target(flow):
            self.block_websocket_flow(flow)
            return

        if self.is_http_relay_target(flow) and not self.relay_ready_for_http():
            self.block_unavailable_http_relay(flow)
            return

        if not self.should_intercept(flow):
            self.pass_through_flow(flow)
            return

        self.relay_http_flow(flow)

    def request(self, flow: http.HTTPFlow) -> None:
        self.log_http_request(flow)
        self.handle_request_flow(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "http_response",
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status_code": flow.response.status_code if flow.response else None,
                "headers": dict(flow.response.headers) if flow.response else {},
                "body_bytes": len(flow.response.raw_content or b"") if flow.response else 0,
            },
        )
        self._print_http_details(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        err = str(flow.error) if flow.error else "unknown"
        self.append_log(
            {
                "ts": self.now_iso(),
                "event": "http_error",
                "url": flow.request.pretty_url if flow.request else "",
                "method": flow.request.method if flow.request else "",
                "host": flow.request.host if flow.request else "",
                "path": flow.request.path if flow.request else "",
                "headers": dict(flow.request.headers) if flow.request else {},
                "body_bytes": len((flow.request.raw_content or b"")) if flow.request else 0,
                "error": err,
            },
        )

        if self.console_log_enabled:
            print("\n" + "💥" + "=" * 60, flush=True)
            self._log("【HTTP Flow Error】")
            if flow.request:
                self._log(f"【URL】: {flow.request.pretty_url}")
                self._log(f"【Method】: {flow.request.method}")
                self._log("\n--- [Request Headers] ---")
                for k, v in flow.request.headers.items():
                    self._log(f"{k}: {v}")
                self._log("\n--- [Request Body] ---")
                self._pretty_print_text(flow.request.get_text(strict=False))
            self._log("\n--- [Error] ---")
            self._log(err)
            self._log("=" * 62 + "\n")

addons = [CodexChunkRelayAddon()]
