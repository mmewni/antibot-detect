"""PerimeterX / HUMAN Security bot defense detector."""
from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection
from antibot_detect.fetcher import FetchResult


class PerimeterXDetector(Detector):
    name = "PerimeterX / HUMAN"

    _COOKIE_PREFIXES = ["_px", "_pxhd", "_pxvid", "_px2", "_px3", "pxcts"]

    _BODY_MARKERS = [
        "/api/v1/px/",
        "client.perimeterx.net",
        "captcha.px-cdn.net",
        "collector-px",
        "px-captcha",
        "window._pxAppId",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        seen: set[str] = set()
        for prefix in self._COOKIE_PREFIXES:
            for cookie in result.cookies_with_prefix(prefix):
                if cookie in seen:
                    continue
                seen.add(cookie)
                evidence.append(f"Cookie {cookie} present")
                strong += 1

        for marker in result.find_in_body(self._BODY_MARKERS):
            evidence.append(f"Body marker: {marker}")
            strong += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
