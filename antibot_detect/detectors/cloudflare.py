from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection, truncate
from antibot_detect.fetcher import FetchResult


class CloudflareDetector(Detector):
    name = "Cloudflare"

    _STRONG_BODY = [
        "/cdn-cgi/challenge-platform/",
    ]
    _WEAK_BODY = [
        "just a moment...",
        "checking your browser",
        "cf-error-details",
        "window._cf_chl_opt",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        ray = result.header("cf-ray")
        if ray:
            evidence.append(f"Header cf-ray: {truncate(ray)}")
            strong += 1

        cache = result.header("cf-cache-status")
        if cache:
            evidence.append(f"Header cf-cache-status: {truncate(cache)}")
            strong += 1

        srv = result.header("server")
        if srv and "cloudflare" in srv.lower():
            evidence.append(f"Header server: {truncate(srv)}")
            strong += 1

        for k, v in result.headers_with_prefix("cf-"):
            if k.lower() in {"cf-ray", "cf-cache-status"}:
                continue
            evidence.append(f"Header {k}: {truncate(v)}")
            weak += 1

        if result.has_cookie("__cf_bm"):
            evidence.append("Cookie __cf_bm present (Bot Management)")
            strong += 1
        if result.has_cookie("cf_clearance"):
            evidence.append("Cookie cf_clearance present (challenge clearance)")
            strong += 1

        for marker in result.find_in_body(self._STRONG_BODY):
            evidence.append(f"Body marker: {marker}")
            strong += 1
        for marker in result.find_in_body(self._WEAK_BODY):
            evidence.append(f"Body marker: {marker!r}")
            weak += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
