from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection
from antibot_detect.fetcher import FetchResult


class RecaptchaDetector(Detector):
    name = "reCAPTCHA"

    _STRONG_MARKERS = [
        "google.com/recaptcha/api.js",
        "gstatic.com/recaptcha/",
        "www.google.com/recaptcha/",
    ]
    _WEAK_MARKERS = [
        "grecaptcha",
        "g-recaptcha",
        "data-sitekey",
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
