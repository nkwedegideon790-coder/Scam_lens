"""Shared helpers: logging, text normalisation, hashing, rate limiting, file parsing."""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from collections import defaultdict, deque
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

from .errors import InvalidInputError, UnsupportedFileError

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def normalize_text(text: str) -> str:
    """Strip control/zero-width characters and collapse excess whitespace."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_RE.sub("", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def text_hash(text: str) -> str:
    canonical = " ".join(text.lower().split())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class RateLimiter:
    """Small in-memory sliding-window limiter (per process)."""

    def __init__(self, window: float = 60.0):
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, max_calls: int) -> bool:
        if max_calls <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= max_calls:
                return False
            q.append(now)
            if len(self._hits) > 5000:  # keep memory bounded
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


# ---------------------------------------------------------------- file parsing
class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._skip = 0
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor_text = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href:
            self.links.append((self._href, " ".join("".join(self._anchor_text).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


def html_to_text(html: str) -> tuple[str, list[str]]:
    parser = _HTMLText()
    parser.feed(html)
    text = "".join(parser.parts)
    links: list[str] = []
    for href, label in parser.links:
        if not href.lower().startswith(("http://", "https://", "www.")):
            continue
        if label and label.lower() != href.lower() and "." in label:
            links.append(f"{href} (link text shown to reader: {label})")
        else:
            links.append(href)
    return text, links


def decode_text(data: bytes) -> str:
    if b"\x00" in data[:2048]:
        raise UnsupportedFileError("That file looks like a binary file. Upload a plain text (.txt) or email (.eml) file.")
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def parse_eml(data: bytes) -> str:
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
        lines = []
        for header in ("From", "Reply-To", "Subject"):
            value = msg.get(header)
            if value:
                lines.append(f"{header}: {value}")
        body, links = "", []
        part = msg.get_body(preferencelist=("plain", "html"))
        if part is not None:
            content = part.get_content()
            if part.get_content_type() == "text/html":
                body, links = html_to_text(content)
            else:
                body = content
        elif not msg.is_multipart():
            body = msg.get_content() if msg.get_content_maintype() == "text" else ""
        out = "\n".join(lines) + "\n\n" + body
        if links:
            out += "\n\n[Links found in the email]\n" + "\n".join(links[:15])
        names = [a.get_filename() for a in msg.iter_attachments() if a.get_filename()]
        if names:
            out += "\n\n[Attachment names (not opened)]\n" + "\n".join(names[:10])
        return out
    except Exception as exc:  # malformed MIME should never crash the API
        logging.getLogger(__name__).warning("eml parse failed: %s", exc)
        raise UnsupportedFileError("We couldn't read that email file. Try pasting the message text instead.") from exc


def parse_text_upload(filename: str | None, data: bytes) -> str:
    name = (filename or "").lower()
    if name.endswith(".eml"):
        return parse_eml(data)
    if name.endswith((".txt", ".text", ".md")):
        return decode_text(data)
    raise UnsupportedFileError("Only plain text (.txt) and email (.eml) files are supported.")


def client_ip(request, trust_proxy: bool) -> str:
    if trust_proxy:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_non_empty(text: str, min_chars: int) -> None:
    if not text or not any(ch.isalnum() for ch in text):
        raise InvalidInputError("Please paste a message to analyze.")
    if len(text) < min_chars:
        raise InvalidInputError("That message is too short to analyze.")
