"""Context-size safety for model prompts.

Encoded and high-entropy telemetry (base64 PowerShell, hex shellcode, random
tokens) tokenizes far more densely than prose: measured with the Qwen2.5
tokenizer it costs roughly 1.7-2.5 characters per token, versus about 3 for
ordinary JSON. Two safeguards follow:

* Long encoded/high-entropy runs are replaced *in the prompt only* by a bounded,
  self-describing marker (type, length, SHA-256 prefix, short head/tail). The
  evidence store, the raw record and its hash are untouched, so the audit
  record keeps the complete value; any decoded PowerShell text is still shown
  to the model as its own attribute.
* Token counts are estimated conservatively (at most 2 characters per token)
  when no tokenizer is available, and the budget reserves room for the
  response, the chat template and a repair turn.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections import Counter

# Hashes (MD5/SHA-1/SHA-256/SHA-512 hex, up to 128 chars) are indicators an
# analyst needs verbatim, so only longer runs are compacted.
MIN_BLOB_CHARS = 130
MIN_NON_ASCII_CHARS = 64
HEAD_TAIL_CHARS = 12
MAX_CHARS_PER_TOKEN = 2.0

# Runs without whitespace, quotes, backslashes or colons (so Windows paths and
# URLs with a scheme split into short pieces). Includes JWT/API-key punctuation.
_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-.~!*%%]{%d,}" % MIN_BLOB_CHARS)
# A domain followed by a path: a URL/indicator the analyst needs verbatim.
_URLISH = re.compile(r"(?:^|/)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}/")
_HEX = re.compile(r"(?:0x)?[0-9A-Fa-f]+")
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}|[A-Za-z0-9_\-]+={0,2}")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _base64_bytes(blob: str) -> bytes | None:
    if not _B64.fullmatch(blob):
        return None
    try:
        altchars = b"-_" if ("-" in blob or "_" in blob) else None
        return base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=altchars, validate=True)
    except (binascii.Error, ValueError):
        return None


def _looks_utf16le_text(raw: bytes) -> bool:
    if len(raw) < 8 or len(raw) % 2:
        return False
    high = raw[1::2]
    low = raw[0::2]
    return high.count(0) / len(high) > 0.9 and sum(32 <= b < 127 or b in (9, 10, 13) for b in low) / len(low) > 0.9


def classify_blob(blob: str) -> str | None:
    """Return a type label if ``blob`` is encoded/high-entropy data, else None."""
    body = blob[2:] if blob[:2].lower() == "0x" else blob
    if _HEX.fullmatch(blob) and len(body) >= MIN_BLOB_CHARS - 2:
        return "hex"
    if _URLISH.search(blob):
        return None
    raw = _base64_bytes(blob)
    if raw is not None and shannon_entropy(blob) >= 3.5:
        if _looks_utf16le_text(raw):
            return "base64 (UTF-16LE text, e.g. PowerShell -EncodedCommand)"
        try:
            raw.decode("ascii")
            return "base64 (ASCII text)"
        except UnicodeDecodeError:
            return "base64 (binary)"
    if shannon_entropy(blob) >= 4.0:
        return "high-entropy string"
    return None


def describe_blob(blob: str, kind: str) -> str:
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    size = f"chars={len(blob)}"
    if kind == "hex":
        size += f" bytes={len(blob.removeprefix('0x').removeprefix('0X')) // 2}"
    elif kind.startswith("base64"):
        raw = _base64_bytes(blob)
        if raw is not None:
            size += f" bytes={len(raw)}"
    return (f"[[compacted {kind}; {size}; sha256_16={digest}; head={blob[:HEAD_TAIL_CHARS]} "
            f"tail={blob[-HEAD_TAIL_CHARS:]}; full value in evidence store]]")


def compact_blobs(text: str) -> tuple[str, int]:
    """Replace long encoded/high-entropy runs with bounded markers. Returns (text, count)."""
    if not text:
        return text, 0
    count = 0

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        kind = classify_blob(m.group(0))
        if kind is None:
            return m.group(0)
        count += 1
        return describe_blob(m.group(0), kind)

    out = _CANDIDATE.sub(repl, text)
    # Mostly non-ASCII text (e.g. random bytes decoded as UTF-16) is escaped to
    # \\uXXXX in JSON and is extremely token-dense; describe it instead.
    non_ascii = sum(ord(c) > 126 for c in out)
    if len(out) >= MIN_NON_ASCII_CHARS and non_ascii / len(out) > 0.3:
        digest = hashlib.sha256(out.encode("utf-8")).hexdigest()[:16]
        return (f"[[compacted non-ASCII text; chars={len(out)}; non_ascii={non_ascii}; sha256_16={digest}; "
                "full value in evidence store]]"), count + 1
    return out, count


def compact_value(value, counter: list[int]):
    """Recursively compact every string inside a JSON-like value."""
    if isinstance(value, str):
        text, n = compact_blobs(value)
        counter[0] += n
        return text
    if isinstance(value, list):
        return [compact_value(v, counter) for v in value]
    if isinstance(value, dict):
        return {k: compact_value(v, counter) for k, v in value.items()}
    return value


def estimate_tokens(text: str, chars_per_token: float = MAX_CHARS_PER_TOKEN) -> int:
    """Conservative token estimate when no tokenizer is available."""
    cpt = min(chars_per_token, MAX_CHARS_PER_TOKEN)
    return math.ceil(len(text) / cpt)
