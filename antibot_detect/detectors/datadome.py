"""DataDome bot protection detector."""
from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection, truncate
from antibot_detect.fetcher import FetchResult


class DataDomeDetector(Detector):
    name = "DataDome"

    _BODY_MARKERS = [
        "geo.captcha-delivery.com",
        "captcha-delivery.com",
        "js.datadome.co",
        "datadome",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        if result.has_cookie("datadome"):
            evidence.append("Cookie datadome present")
            strong += 1

        for name, value in result.headers_with_prefix("x-datadome"):
            evidence.append(f"Header {name}: {truncate(value)}")
            strong += 1

        matched = result.find_in_body(self._BODY_MARKERS)
        for marker in matched:
            if marker == "datadome":
                if not any("captcha-delivery" in m or "js.datadome" in m for m in matched):
                    evidence.append(f"Body marker: {marker!r}")
                    weak += 1
            else:
                evidence.append(f"Body marker: {marker}")
                strong += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
