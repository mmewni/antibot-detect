from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection
from antibot_detect.fetcher import FetchResult


class TurnstileDetector(Detector):
    name = "Cloudflare Turnstile"

    _STRONG_MARKERS = [
        "challenges.cloudflare.com/turnstile/",
        "challenges.cloudflare.com/turnstile",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        for marker in result.find_in_body(self._STRONG_MARKERS):
            evidence.append(f"Body marker: {marker}")
            strong += 1

        if result.find_in_body(["cf-turnstile"]):
            evidence.append("Body marker: 'cf-turnstile'")
            strong += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
