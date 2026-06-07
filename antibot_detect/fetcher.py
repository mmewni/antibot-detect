from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse

try:
    from curl_cffi.requests.exceptions import (
        ConnectionError as _CurlConnectionError,
        RequestException as _CurlRequestError,
        Timeout as _CurlTimeout,
    )
except ImportError:
    try:
        from curl_cffi.requests.errors import RequestsError as _CurlRequestError
    except ImportError:
        _CurlRequestError = Exception
    _CurlConnectionError = _CurlRequestError
    _CurlTimeout = _CurlRequestError

from curl_cffi import requests as cffi_requests

DEFAULT_IMPERSONATE = "chrome120"
DEFAULT_TIMEOUT = 15
BODY_LIMIT = 500 * 1024

DEFAULT_HEADERS: dict[str, str] = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}


class FetchError(Exception):
    """for when URL cannot be fetched"""
@dataclass
class RedirectHop:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
        }


@dataclass
class FetchResult:
    requestedUrl: str
    finalUrl: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str = ""
    redirectChain: list[RedirectHop] = field(default_factory=list)

    def _header_dicts(self) -> list[dict[str, str]]:
        dicts = [hop.headers for hop in self.redirectChain]
        dicts.append(self.headers)
        return dicts

    def header(self, name: str) -> Optional[str]:
        target = name.lower()
        for hdrs in self._header_dicts():
            for key, value in hdrs.items():
                if key.lower() == target:
                    return value
        return None

    def headers_with_prefix(self, prefix: str) -> list[tuple[str, str]]:
        p = prefix.lower()
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for hdrs in self._header_dicts():
            for key, value in hdrs.items():
                low = key.lower()
                if low.startswith(p) and low not in seen:
                    seen.add(low)
                    out.append((key, value))
        return out

    def header_contains(self, name: str, needle: str) -> bool:
        value = self.header(name)
        return value is not None and needle.lower() in value.lower()

    def all_cookies(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for hop in self.redirectChain:
            merged.update(hop.cookies)
        merged.update(self.cookies)
        return merged

    def has_cookie(self, name: str) -> bool:
        return name in self.all_cookies()

    def cookies_with_prefix(self, prefix: str) -> list[str]:
        return [c for c in self.all_cookies() if c.startswith(prefix)]

    def find_in_body(self, markers: list[str]) -> list[str]:
        if not self.body:
            return []
        low = self.body.lower()
        return [m for m in markers if m.lower() in low]

    def to_dict(self, includeBody: bool = False) -> dict[str, object]:
        data: dict[str, object] = {
            "requested_url": self.requestedUrl,
            "final_url": self.finalUrl,
            "status": self.status,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "redirect_chain": [hop.to_dict() for hop in self.redirectChain],
        }
        if includeBody:
            data["body"] = self.body
        return data


def _normalise_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse("https://" + url)
    if not parsed.netloc:
        raise FetchError(f"Could not parse a host from URL: {url!r}")
    return urlunparse(parsed)


def _cookies_to_dict(jar: object) -> dict[str, str]:
    if jar is None:
        return {}
    try:
        return {str(k): str(v) for k, v in jar.items()}
    except AttributeError:
        return dict(jar)


def fetch(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    impersonate: str = DEFAULT_IMPERSONATE,
) -> FetchResult:
    target = _normalise_url(url)

    last: Optional[Exception] = None
    response = None
    for _ in range(2):
        try:
            with cffi_requests.Session(impersonate=impersonate) as session:
                response = session.get(
                    target,
                    headers=DEFAULT_HEADERS,
                    timeout=timeout,
                    allow_redirects=True,
                )
            break
        except _CurlTimeout as exc:
            raise FetchError(f"Request to {target} timed out after {timeout}s.") from exc
        except _CurlConnectionError as exc:
            last = exc
        except _CurlRequestError as exc:
            raise FetchError(f"Failed to fetch {target}: {exc}") from exc

    if response is None:
        raise FetchError(f"Could not connect to {target} after 2 attempts: {last}")

    chain: list[RedirectHop] = []
    for hop in getattr(response, "history", []) or []:
        chain.append(
            RedirectHop(
                url=str(getattr(hop, "url", "")),
                status=int(getattr(hop, "status_code", 0) or 0),
                headers=dict(getattr(hop, "headers", {}) or {}),
                cookies=_cookies_to_dict(getattr(hop, "cookies", None)),
            )
        )

    body = response.text or ""
    if len(body) > BODY_LIMIT:
        body = body[:BODY_LIMIT]

    return FetchResult(
        requestedUrl=target,
        finalUrl=str(response.url),
        status=int(response.status_code),
        headers=dict(response.headers),
        cookies=_cookies_to_dict(response.cookies),
        body=body,
        redirectChain=chain,
    )
