from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection, truncate
from antibot_detect.fetcher import FetchResult


class KasadaDetector(Detector):
    name = "Kasada"

    _BODY_MARKERS = [
        "/ips.js",
        "kpsdk",
        "kasada",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        for name, value in result.headers_with_prefix("x-kpsdk-"):
            evidence.append(f"Header {name}: {truncate(value)}")
            strong += 1

        for marker in result.find_in_body(self._BODY_MARKERS):
            if marker == "/ips.js":
                evidence.append(f"Body marker: {marker}")
                strong += 1
            else:
                evidence.append(f"Body marker: {marker!r}")
                weak += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
