"""hCaptcha detector (body markers only)."""
from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection
from antibot_detect.fetcher import FetchResult


class HcaptchaDetector(Detector):
    name = "hCaptcha"

    _STRONG_MARKERS = [
        "hcaptcha.com/1/api.js",
        "js.hcaptcha.com",
        "newassets.hcaptcha.com",
    ]
    _WEAK_MARKERS = [
        "h-captcha",
        "data-hcaptcha-sitekey",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        for marker in result.find_in_body(self._STRONG_MARKERS):
            evidence.append(f"Body marker: {marker}")
            strong += 1
        for marker in result.find_in_body(self._WEAK_MARKERS):
            evidence.append(f"Body marker: {marker!r}")
            weak += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
