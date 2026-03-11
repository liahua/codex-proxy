#!/usr/bin/env python3
"""
Codex request chunking addon for mitmproxy.

When a matched request body exceeds the configured threshold, this addon:
1. uploads request metadata to the external relay service
2. uploads the body in smaller chunks
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
from base64 import b64encode

from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from mitmproxy import ctx, http


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
    scheme = parsed.scheme
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    query = parsed.query
    return scheme, host, port, path, query


def map_scheme_for_flow(scheme: str) -> str:
    if scheme == "ws":
        return "http"
    if scheme == "wss":
        return "https"
    return scheme


def http_request(method: str, url: str, headers=None, body: bytes | None = None, timeout: int = 120):
    req = Request(url=url, data=body, headers=headers or {}, method=method)
    return urlopen(req, timeout=timeout)



class CodexChunkRelayAddon:
    def __init__(self):
        self.enabled = env_bool("CHUNK_RELAY_ENABLED", True)
        self.relay_base_url = os.getenv("CHUNK_RELAY_BASE_URL", "").rstrip("/")
        self.shared_secret = os.getenv("CHUNK_RELAY_SHARED_SECRET", "")
        self.threshold_bytes = env_int("CHUNK_RELAY_THRESHOLD_BYTES", 100 * 1024)
        self.chunk_size_bytes = env_int("CHUNK_RELAY_CHUNK_SIZE_BYTES", 20 * 1024)
        self.timeout_seconds = env_int("CHUNK_RELAY_TIMEOUT_SECONDS", 120)
        self.upload_retries = env_int("CHUNK_RELAY_UPLOAD_RETRIES", 3)
        self.retry_backoff_ms = env_int("CHUNK_RELAY_RETRY_BACKOFF_MS", 400)
        self.match_hosts = {
            item.strip().lower()
            for item in os.getenv("CHUNK_RELAY_MATCH_HOSTS", "127.0.0.1,localhost").split(",")
            if item.strip()
        }
        self.match_paths = {
            item.strip()
            for item in os.getenv("CHUNK_RELAY_MATCH_PATHS", "/v1/responses").split(",")
            if item.strip()
        }
        self.header_allowlist = {
            item.strip().lower()
            for item in os.getenv(
                "CHUNK_RELAY_HEADER_ALLOWLIST",
                "authorization,content-type,accept,user-agent,statsig-api-key,"
                "x-session-id,x-codex-session-id"
            ).split(",")
            if item.strip()
        }
        self.http_log_path = os.getenv("HTTP_INSPECT_LOG_PATH", "")
        self.ws_log_path = os.getenv("WS_INSPECT_LOG_PATH", "")
        self.ws_enabled = env_bool("CHUNK_RELAY_WS_ENABLED", False)
        self.ws_relay_url = os.getenv("CHUNK_RELAY_WS_BASE_URL", "").rstrip("/")
        self.ws_match_hosts = {
            item.strip().lower()
            for item in os.getenv("CHUNK_RELAY_WS_MATCH_HOSTS", "chatgpt.com").split(",")
            if item.strip()
        }
        self.ws_match_paths = {
            item.strip()
            for item in os.getenv("CHUNK_RELAY_WS_MATCH_PATHS", "/backend-api/codex/responses").split(",")
            if item.strip()
        }
        self.ws_threshold_bytes = env_int("CHUNK_RELAY_WS_THRESHOLD_BYTES", 100 * 1024)
        self.ws_chunk_size_bytes = env_int("CHUNK_RELAY_WS_CHUNK_SIZE_BYTES", 20 * 1024)
        self.ws_mode = os.getenv("CHUNK_RELAY_WS_MODE", "ws").strip().lower()
        self.ws_http_url = os.getenv("CHUNK_RELAY_WS_HTTP_URL", "").rstrip("/")
        self.relay_chunk_field = "__relay_chunk_v1"

    def load(self, loader):
        ctx.log.info(
            "chunk relay addon loaded: "
            f"enabled={self.enabled}, relay_base_url={self.relay_base_url or '<empty>'}, "
            f"threshold={self.threshold_bytes}, chunk_size={self.chunk_size_bytes}"
        )

    def append_log(self, path: str, payload: dict) -> None:
        if not path:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def should_intercept(self, flow: http.HTTPFlow) -> bool:
        if not self.enabled or not self.relay_base_url:
            return False
        if flow.request.method.upper() != "POST":
            return False
        if flow.request.host.lower() not in self.match_hosts:
            return False
        if flow.request.path.split("?", 1)[0] not in self.match_paths:
            return False
        body = flow.request.raw_content or b""
        if len(body) <= self.threshold_bytes:
            return False
        return True

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
            "host_match": host in self.match_hosts,
            "path_match": path in self.match_paths,
            "threshold_bytes": self.threshold_bytes,
        }
        self.append_log(self.http_log_path, payload)
        ctx.log.info(
            "http relay decision "
            f"method={payload['method']} host={payload['host']} path={payload['path']} "
            f"body={payload['body_bytes']} enabled={payload['enabled']} "
            f"relay_base_url={'set' if payload['relay_base_url_set'] else 'empty'} "
            f"host_match={payload['host_match']} path_match={payload['path_match']} "
            f"threshold={payload['threshold_bytes']}"
        )

    def should_rewrite_ws(self, flow: http.HTTPFlow) -> bool:
        if not self.ws_enabled or not self.ws_relay_url:
            return False
        if flow.request.method.upper() != "GET":
            return False
        if flow.request.host.lower() not in self.ws_match_hosts:
            return False
        if flow.request.path.split("?", 1)[0] not in self.ws_match_paths:
            return False
        upgrade = flow.request.headers.get("upgrade", "")
        return upgrade.lower() == "websocket"

    def should_proxy_ws_via_http(self, flow: http.HTTPFlow) -> bool:
        if self.ws_mode != "http":
            return False
        if not self.ws_enabled:
            return False
        if flow.request.host.lower() not in self.ws_match_hosts:
            return False
        if flow.request.path.split("?", 1)[0] not in self.ws_match_paths:
            return False
        return True

    def ws_http_endpoint(self) -> str:
        if self.ws_http_url:
            return self.ws_http_url
        if self.relay_base_url:
            return urljoin(f"{self.relay_base_url}/", "relay/v1/codex/ws-http")
        return ""

    def stream_ws_http_event(self, flow: http.HTTPFlow, message) -> None:
        endpoint = self.ws_http_endpoint()
        if not endpoint:
            raise RuntimeError("CHUNK_RELAY_WS_HTTP_URL or CHUNK_RELAY_BASE_URL is required when CHUNK_RELAY_WS_MODE=http")

        raw = message.content
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        payload = {
            "event": json.loads(raw),
            "headers": self.build_forward_headers(flow),
            "url": flow.metadata.get("relay_ws_original_url", flow.request.pretty_url),
        }
        headers = self.relay_headers()
        headers["accept"] = "text/event-stream"
        headers["content-type"] = "application/json"

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        with http_request("POST", endpoint, headers=headers, body=body, timeout=self.timeout_seconds) as response:
            for raw_line in response:
                if not raw_line:
                    continue
                text = raw_line.decode("utf-8", errors="replace").strip()
                if not text.startswith("data:"):
                    continue
                data = text[5:].strip()
                if not data:
                    continue
                ctx.master.commands.call(
                    "inject.websocket",
                    flow,
                    True,
                    data.encode("utf-8"),
                    False,
                )

    def build_forward_headers(self, flow: http.HTTPFlow) -> dict:
        forwarded = {}
        for key, value in flow.request.headers.items():
            lowered = key.lower()
            if lowered in self.header_allowlist:
                forwarded[lowered] = value
        return forwarded

    def relay_headers(self) -> dict:
        headers = {"content-type": "application/json"}
        if self.shared_secret:
            headers["x-relay-secret"] = self.shared_secret
        return headers

    def sha256_hex(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def request_with_retry(self, method: str, url: str, headers=None, content: bytes | None = None):
        last_error = None
        for attempt in range(self.upload_retries + 1):
            try:
                response = http_request(method, url, headers=headers or {}, body=content, timeout=self.timeout_seconds)
                return response
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if attempt >= self.upload_retries:
                    break
                sleep_seconds = (self.retry_backoff_ms * (2 ** attempt)) / 1000.0
                time.sleep(sleep_seconds)
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
            "headerAllowlist": sorted(self.header_allowlist),
            "bodySize": len(body),
            "bodySha256": self.sha256_hex(body),
            "chunkCount": chunk_count,
        }

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
        url = urljoin(f"{self.relay_base_url}/", "relay/v1/chunked/complete")
        scheme, host, port, path, query = parse_url(url)
        flow.request.scheme = scheme
        flow.request.host = host
        flow.request.port = port or (443 if scheme == "https" else 80)
        flow.request.path = f"{path}?{query}" if query else path
        flow.request.method = "POST"
        flow.request.headers.clear()
        flow.request.headers["host"] = host
        flow.request.headers["content-type"] = "application/json"
        flow.request.headers["accept"] = "text/event-stream"
        if self.shared_secret:
            flow.request.headers["x-relay-secret"] = self.shared_secret
        flow.request.text = json.dumps({"requestId": request_id}, ensure_ascii=False)
        self.append_log(
            self.http_log_path,
            {
                "ts": self.now_iso(),
                "event": "http_relay_rewrite",
                "request_id": request_id,
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "body_bytes": len(flow.request.raw_content or b""),
            },
        )

    def request(self, flow: http.HTTPFlow) -> None:
        self.append_log(
            self.http_log_path,
            {
                "ts": self.now_iso(),
                "event": "http_request",
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "body_bytes": len(flow.request.raw_content or b""),
            },
        )

        if self.should_rewrite_ws(flow):
            original_url = flow.request.pretty_url
            relay_scheme_raw, relay_host, relay_port, relay_path_raw, relay_query = parse_url(self.ws_relay_url)
            relay_scheme = map_scheme_for_flow(relay_scheme_raw)
            flow.metadata["relay_ws_enabled"] = True
            flow.metadata["relay_ws_http_enabled"] = self.should_proxy_ws_via_http(flow)
            flow.metadata["relay_ws_original_url"] = original_url
            flow.request.scheme = relay_scheme
            flow.request.host = relay_host
            flow.request.port = relay_port or (443 if relay_scheme == "https" else 80)
            relay_path = f"{relay_path_raw}?{relay_query}" if relay_query else relay_path_raw
            flow.request.path = relay_path
            flow.request.headers["host"] = relay_host
            flow.request.headers["x-relay-upstream-url"] = original_url.replace("https://", "wss://", 1)
            if self.shared_secret:
                flow.request.headers["x-relay-secret"] = self.shared_secret
            return

        if not self.should_intercept(flow):
            if flow.request.method.upper() == "POST":
                body = flow.request.raw_content or b""
                path = flow.request.path.split("?", 1)[0]
                if len(body) > self.threshold_bytes or flow.request.host.lower() in self.match_hosts or path in self.match_paths:
                    self.log_intercept_decision(flow)
            return

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
        except Exception as exc:
            ctx.log.error(f"chunk relay failed: {exc}")
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

    def response(self, flow: http.HTTPFlow) -> None:
        self.append_log(
            self.http_log_path,
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

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        self.append_log(
            self.ws_log_path,
            {
                "ts": self.now_iso(),
                "event": "websocket_start",
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
            },
        )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if not flow.websocket or not flow.websocket.messages:
            return
        message = flow.websocket.messages[-1]
        if message.injected:
            return
        content = message.content
        preview = None
        if isinstance(content, bytes):
            preview = content[:200].decode("utf-8", errors="replace")
            size = len(content)
            opcode = "bytes"
        else:
            preview = content[:200]
            size = len(content)
            opcode = "text"

        self.append_log(
            self.ws_log_path,
            {
                "ts": self.now_iso(),
                "event": "websocket_message",
                "url": flow.request.pretty_url,
                "from_client": message.from_client,
                "content_type": opcode,
                "bytes": size,
                "preview": preview,
            },
        )

        if not flow.metadata.get("relay_ws_enabled"):
            return
        if not message.from_client:
            return

        if flow.metadata.get("relay_ws_http_enabled"):
            try:
                message.drop()
                self.stream_ws_http_event(flow, message)
            except Exception as exc:
                ctx.log.error(f"ws http relay failed: {exc}")
                flow.websocket.close(code=1011, reason=f"ws_http_relay_failed: {exc}")
            return

        if len(message.content) <= self.ws_threshold_bytes:
            return

        message.drop()
        chunk_id = uuid.uuid4().hex
        total = math.ceil(len(message.content) / self.ws_chunk_size_bytes)
        payload_sha = self.sha256_hex(message.content)
        self.append_log(
            self.ws_log_path,
            {
                "ts": self.now_iso(),
                "event": "websocket_chunk_split",
                "url": flow.request.pretty_url,
                "chunk_id": chunk_id,
                "original_bytes": len(message.content),
                "chunk_size_bytes": self.ws_chunk_size_bytes,
                "chunk_count": total,
            },
        )

        for index in range(total):
            start = index * self.ws_chunk_size_bytes
            end = start + self.ws_chunk_size_bytes
            chunk = message.content[start:end]
            envelope = {
                self.relay_chunk_field: {
                    "id": chunk_id,
                    "index": index,
                    "total": total,
                    "sha256": payload_sha,
                    "total_bytes": len(message.content),
                    "is_text": message.is_text,
                },
                "data": b64encode(chunk).decode("ascii"),
            }
            ctx.master.commands.call(
                "inject.websocket",
                flow,
                False,
                json.dumps(envelope, ensure_ascii=False).encode("utf-8"),
                True,
            )

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        self.append_log(
            self.ws_log_path,
            {
                "ts": self.now_iso(),
                "event": "websocket_end",
                "url": flow.request.pretty_url,
                "close_code": getattr(flow.websocket, "close_code", None) if flow.websocket else None,
            },
        )


addons = [CodexChunkRelayAddon()]
