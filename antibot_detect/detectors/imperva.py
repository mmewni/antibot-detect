from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection, truncate
from antibot_detect.fetcher import FetchResult


class ImpervaDetector(Detector):
    name = "Imperva / Incapsula"

    _COOKIE_PREFIXES = ["incap_ses_", "visid_incap_", "nlbi_", "reese84"]

    _BODY_MARKERS = [
        "_incapsula_resource",
        "incapsula incident",
        "subject=waf+block+page",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        seen: set[str] = set()
        for prefix in self._COOKIE_PREFIXES:
            for c in result.cookies_with_prefix(prefix):
                if c in seen:
                    continue
                seen.add(c)
                evidence.append(f"Cookie {c} present")
                strong += 1

        iinfo = result.header("x-iinfo")
        if iinfo is not None:
            evidence.append(f"Header X-Iinfo: {truncate(iinfo)}")
            strong += 1

        cdn = result.header("x-cdn")
        if cdn and "incapsula" in cdn.lower():
            evidence.append(f"Header X-CDN: {truncate(cdn)}")
            strong += 1

        for marker in result.find_in_body(self._BODY_MARKERS):
            evidence.append(f"Body marker: {marker!r}")
            strong += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
