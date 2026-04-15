#!/usr/bin/env python3
"""
Record-only mitmproxy addon for Codex traffic inspection.

This addon never rewrites, blocks, or proxies traffic through an external
relay. It only records matched HTTP/WebSocket traffic and lets the original
request continue upstream unchanged.
"""

import base64
import gzip
import hashlib
import json
import os
import zlib
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import ctx, http

REDACTED_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
}

DEFAULT_MATCH_HOSTS = "chatgpt.com,.chatgpt.com,openai.com,.openai.com"

try:
    import brotli
except ImportError:
    brotli = None


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


class CodexRecordOnlyAddon:
    def __init__(self):
        self.match_hosts = {
            item.strip().lower()
            for item in os.getenv("MITM_RECORD_MATCH_HOSTS", DEFAULT_MATCH_HOSTS).split(",")
            if item.strip()
        }
        self.console_log_enabled = env_bool("MITM_RECORD_CONSOLE_LOG", True)
        self.body_max_bytes = env_int("MITM_RECORD_BODY_MAX_BYTES", 0)
        self.output_file = os.getenv("MITM_RECORD_OUTPUT_FILE", "").strip()
        self.error_output_file = os.getenv("MITM_ERROR_LOG_FILE", "").strip()
        self.error_body_max_bytes = env_int("MITM_ERROR_BODY_MAX_BYTES", 8192)

    def load(self, loader):
        scope = sorted(self.match_hosts) if self.match_hosts else ["<all-hosts>"]
        if self.output_file:
            Path(self.output_file).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        if self.error_output_file:
            Path(self.error_output_file).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        ctx.log.info(
            "record-only addon loaded: "
            f"matched_hosts={scope}, console_log={self.console_log_enabled}, "
            f"body_max_bytes={self.body_max_bytes}, output_file={self.output_file or '<mitm-log>'}, "
            f"error_output_file={self.error_output_file or '<disabled>'}"
        )

    def _log(self, msg: str = "") -> None:
        if self.console_log_enabled:
            print(msg, flush=True)

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def host_matches(self, host: str | None) -> bool:
        if not self.match_hosts:
            return True

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

    def _sanitize_headers(self, headers: dict) -> dict:
        sanitized = {}
        for key, value in (headers or {}).items():
            lowered = str(key).lower()
            sanitized[lowered] = "<redacted>" if lowered in REDACTED_HEADER_KEYS else str(value)
        return sanitized

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

    def _serialize_bytes(self, data: bytes, headers: dict | None = None, limit: int | None = None) -> dict:
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
                decoded = self._decode_content_encoding(raw, content_encoding)
                decoded_bytes, decoded_via = decoded
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

    def _coerce_message_content(self, content) -> bytes:
        if content is None:
            return b""
        if isinstance(content, bytes):
            return content
        if isinstance(content, str):
            return content.encode("utf-8")
        return bytes(content)

    def append_log(self, prefix: str, payload: dict) -> None:
        line = f"{prefix} {json.dumps(payload, ensure_ascii=False)}"
        if self.output_file:
            with Path(self.output_file).expanduser().resolve().open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.write("\n")
            return
        ctx.log.info(line)

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
        if not self.should_record_http(flow):
            return
        status_code = flow.response.status_code if flow.response else None
        if not error and status_code is not None and 200 <= status_code < 300:
            return

        request_headers = dict(flow.request.headers) if flow.request else {}
        response_headers = dict(flow.response.headers) if flow.response else {}
        self.append_error_log(
            {
                "ts": self.now_iso(),
                "event": "http_error_summary",
                "flow_id": flow.id,
                "method": flow.request.method if flow.request else "",
                "url": flow.request.pretty_url if flow.request else "",
                "host": flow.request.host if flow.request else "",
                "path": flow.request.path if flow.request else "",
                "status_code": status_code,
                "reason": getattr(flow.response, "reason", "") if flow.response else "",
                "error": error,
                "request_headers": self._sanitize_headers(request_headers),
                "request_body": self._serialize_bytes(
                    flow.request.raw_content or b"",
                    request_headers,
                    limit=self.error_body_max_bytes,
                ) if flow.request else self._serialize_bytes(b"", limit=self.error_body_max_bytes),
                "response_headers": self._sanitize_headers(response_headers),
                "response_body": self._serialize_bytes(
                    flow.response.raw_content or b"",
                    response_headers,
                    limit=self.error_body_max_bytes,
                ) if flow.response else self._serialize_bytes(b"", limit=self.error_body_max_bytes),
            }
        )

    def should_record_http(self, flow: http.HTTPFlow) -> bool:
        return self.host_matches(flow.request.host)

    def should_record_ws(self, flow: http.HTTPFlow) -> bool:
        return self.host_matches(flow.request.host)

    def request(self, flow: http.HTTPFlow) -> None:
        if not self.should_record_http(flow):
            return

        payload = {
            "ts": self.now_iso(),
            "event": "http_request",
            "flow_id": flow.id,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "port": flow.request.port,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
            "headers": self._sanitize_headers(dict(flow.request.headers)),
            "body": self._serialize_bytes(flow.request.raw_content or b"", dict(flow.request.headers)),
        }
        self.append_log("http_inspect", payload)
        self._log(
            f"[record-only] request flow_id={flow.id} method={flow.request.method} "
            f"url={flow.request.pretty_url} bytes={len(flow.request.raw_content or b'')}"
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.should_record_http(flow):
            return

        self.maybe_log_error_summary(flow)
        payload = {
            "ts": self.now_iso(),
            "event": "http_response",
            "flow_id": flow.id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "status_code": flow.response.status_code if flow.response else None,
            "reason": getattr(flow.response, "reason", "") if flow.response else "",
            "http_version": getattr(flow.response, "http_version", "") if flow.response else "",
            "headers": self._sanitize_headers(dict(flow.response.headers)) if flow.response else {},
            "body": self._serialize_bytes(flow.response.raw_content or b"", dict(flow.response.headers)) if flow.response else self._serialize_bytes(b""),
        }
        self.append_log("http_inspect", payload)
        self._log(
            f"[record-only] response flow_id={flow.id} status={payload['status_code']} "
            f"url={flow.request.pretty_url} bytes={len(flow.response.raw_content or b'') if flow.response else 0}"
        )

    def error(self, flow: http.HTTPFlow) -> None:
        if not self.should_record_http(flow):
            return

        error = str(flow.error) if flow.error else "unknown"
        self.maybe_log_error_summary(flow, error)
        payload = {
            "ts": self.now_iso(),
            "event": "http_error",
            "flow_id": flow.id,
            "method": flow.request.method if flow.request else "",
            "url": flow.request.pretty_url if flow.request else "",
            "headers": self._sanitize_headers(dict(flow.request.headers)) if flow.request else {},
            "body": self._serialize_bytes(flow.request.raw_content or b"", dict(flow.request.headers)) if flow.request else self._serialize_bytes(b""),
            "error": error,
        }
        self.append_log("http_inspect", payload)
        self._log(f"[record-only] error flow_id={flow.id} error={payload['error']}")

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        if not self.should_record_ws(flow):
            return

        payload = {
            "ts": self.now_iso(),
            "event": "websocket_start",
            "flow_id": flow.id,
            "url": flow.request.pretty_url,
            "request_headers": self._sanitize_headers(dict(flow.request.headers)),
            "response_status_code": flow.response.status_code if flow.response else None,
            "response_headers": self._sanitize_headers(dict(flow.response.headers)) if flow.response else {},
        }
        self.append_log("ws_inspect", payload)
        self._log(f"[record-only] websocket_start flow_id={flow.id} url={flow.request.pretty_url}")

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if not self.should_record_ws(flow):
            return
        if not flow.websocket or not flow.websocket.messages:
            return

        message = flow.websocket.messages[-1]
        payload = {
            "ts": self.now_iso(),
            "event": "websocket_message",
            "flow_id": flow.id,
            "url": flow.request.pretty_url,
            "from_client": bool(message.from_client),
            "message_type": "text" if message.is_text else "binary",
            "content": self._serialize_bytes(self._coerce_message_content(message.content)),
        }
        self.append_log("ws_inspect", payload)
        self._log(
            f"[record-only] websocket_message flow_id={flow.id} from_client={payload['from_client']} "
            f"type={payload['message_type']} bytes={payload['content']['total_bytes']}"
        )

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        if not self.should_record_ws(flow):
            return

        payload = {
            "ts": self.now_iso(),
            "event": "websocket_end",
            "flow_id": flow.id,
            "url": flow.request.pretty_url,
            "close_code": getattr(flow.websocket, "close_code", None) if flow.websocket else None,
            "close_reason": getattr(flow.websocket, "close_reason", "") if flow.websocket else "",
            "message_count": len(flow.websocket.messages) if flow.websocket else 0,
        }
        self.append_log("ws_inspect", payload)
        self._log(
            f"[record-only] websocket_end flow_id={flow.id} "
            f"messages={payload['message_count']} close_code={payload['close_code']}"
        )


addons = [CodexRecordOnlyAddon()]
