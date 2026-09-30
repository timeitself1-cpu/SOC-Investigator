"""Classified, redacted failures for backends and models.

Raw exception text from HTTP clients and search engines can contain URLs,
response bodies, echoed queries or credential fragments. Nothing that crosses
into the audit trace, the UI, or a model prompt should carry that text. Every
failure is reduced to a stable ``kind`` plus a fixed, safe message.
"""

from __future__ import annotations

import ssl
from typing import Literal

import httpx

ErrorKind = Literal[
    "timeout",          # request exceeded its deadline
    "tls",              # certificate / TLS handshake failure
    "auth",             # 401: credentials missing, wrong or expired
    "permission",       # 403: authenticated but not authorised for the index/API
    "not_found",        # 404 on a specific resource
    "index_missing",    # the configured index pattern matched no index
    "mapping",          # query rejected: field/type mismatch with the index mapping
    "partial_results",  # shard failures / timed-out search / incomplete response
    "invalid_response", # malformed payload or unparseable record
    "rate_limited",     # 429
    "unavailable",      # connection refused, DNS, 5xx
    "source_unavailable",  # the telemetry source does not exist / is not installed / not local
    "model_output",     # model returned unusable output (truncated, empty, invalid)
    "invalid_argument", # the model's tool request referenced something invalid
    "cancelled",
    "internal",         # unexpected application error
]

SAFE_MESSAGES: dict[str, str] = {
    "timeout": "The request timed out.",
    "tls": "TLS verification failed (check the CA bundle / certificate).",
    "auth": "Authentication failed (credentials missing, wrong or expired).",
    "permission": "The account is not authorised for this index or API.",
    "not_found": "The requested resource was not found.",
    "index_missing": "The configured index pattern matched no index (for example, archives are not enabled).",
    "mapping": "The query was rejected; field names or types differ from the expected mapping.",
    "partial_results": "The search returned partial or failed shard results.",
    "invalid_response": "The service returned a malformed response or record.",
    "rate_limited": "The service is rate limiting requests.",
    "unavailable": "The service could not be reached or returned a server error.",
    "source_unavailable": "The telemetry source is not available on this computer.",
    "model_output": "The model returned unusable output.",
    "invalid_argument": "The tool request was invalid.",
    "cancelled": "The operation was cancelled.",
    "internal": "An unexpected internal error occurred.",
}


class ClassifiedError(RuntimeError):
    """An error with a stable kind and a message safe to display anywhere."""

    def __init__(self, kind: str, message: str | None = None, *, status_code: int | None = None) -> None:
        self.kind = kind if kind in SAFE_MESSAGES else "internal"
        self.status_code = status_code
        self.safe_message = message or SAFE_MESSAGES[self.kind]
        super().__init__(self.safe_message)


def _chain(exc: BaseException):
    seen = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        yield cur
        cur = cur.__cause__ or cur.__context__


def classify_http_status(status: int, body_text: str = "") -> str:
    """Map an HTTP status (and, for 400/404, the error *type* in the body) to a kind.

    The body is only inspected for well-known error-type tokens; it is never
    copied into the message.
    """
    lowered = body_text[:4000].lower()
    if status == 401:
        return "auth"
    if status == 403:
        return "permission"
    if status == 404:
        return "index_missing" if "index_not_found" in lowered else "not_found"
    if status == 429:
        return "rate_limited"
    if status == 400:
        if any(t in lowered for t in ("query_shard_exception", "illegal_argument_exception",
                                      "no mapping found", "failed to create query",
                                      "search_phase_execution_exception", "parsing_exception")):
            return "mapping"
        return "invalid_response"
    if 500 <= status < 600:
        return "unavailable"
    return "invalid_response"


def classify_exception(exc: BaseException) -> ClassifiedError:
    """Reduce any exception to a ClassifiedError. Never returns raw text."""
    if isinstance(exc, ClassifiedError):
        return exc
    for cause in _chain(exc):
        if isinstance(cause, ClassifiedError):
            return cause
        if isinstance(cause, httpx.TimeoutException):
            return ClassifiedError("timeout")
        if isinstance(cause, ssl.SSLError) or "certificate_verify_failed" in type(cause).__name__.lower():
            return ClassifiedError("tls")
        if isinstance(cause, httpx.HTTPStatusError):
            status = cause.response.status_code
            try:
                body = cause.response.text
            except Exception:  # noqa: BLE001 - streamed / undecodable body
                body = ""
            return ClassifiedError(classify_http_status(status, body), status_code=status)
    # TLS failures surface as ConnectError whose text names the SSL problem.
    for cause in _chain(exc):
        text = str(cause).lower()
        if isinstance(cause, httpx.ConnectError) and ("ssl" in text or "certificate" in text):
            return ClassifiedError("tls")
        if isinstance(cause, (httpx.ConnectError, httpx.NetworkError, httpx.RemoteProtocolError)):
            return ClassifiedError("unavailable")
    if isinstance(exc, (ValueError, KeyError, TypeError)):
        return ClassifiedError("invalid_response")
    return ClassifiedError("internal")


def safe_error(exc: BaseException) -> tuple[str, str]:
    """(kind, message) for display/audit. The message never contains exception text."""
    c = classify_exception(exc)
    suffix = f" (HTTP {c.status_code})" if c.status_code else ""
    return c.kind, c.safe_message + suffix
