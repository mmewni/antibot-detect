from __future__ import annotations

from antibot_detect.fetcher import FetchResult, RedirectHop


def make_result(
    *,
    url: str = "https://example.com/",
    status: int = 200,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    body: str = "",
    redirectChain: list[RedirectHop] | None = None,
) -> FetchResult:
    return FetchResult(
        requestedUrl=url,
        finalUrl=url,
        status=status,
        headers=headers or {},
        cookies=cookies or {},
        body=body,
        redirectChain=redirectChain or [],
    )
