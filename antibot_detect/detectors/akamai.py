"""Akamai (CDN + Bot Manager) detector."""
from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection, truncate
from antibot_detect.fetcher import FetchResult


class AkamaiDetector(Detector):
    name = "Akamai Bot Manager"

    _BOT_COOKIES = ["_abck", "bm_sz", "bm_sv", "ak_bmsc", "bm_mi", "bm_so"]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        srv = result.header("server") or ""
        if "akamai" in srv.lower():
            evidence.append(f"Header server: {truncate(srv)}")
            strong += 1

        hdrs = result.headers_with_prefix("x-akamai-") + result.headers_with_prefix("akamai-")
        for k, v in hdrs:
            evidence.append(f"Header {k}: {truncate(v)}")
            weak += 1

        for c in self._BOT_COOKIES:
            if result.has_cookie(c):
                note = " (Bot Manager sensor)" if c == "_abck" else ""
                evidence.append(f"Cookie {c} present{note}")
                if c in {"_abck", "ak_bmsc", "bm_sz"}:
                    strong += 1
                else:
                    weak += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
