"""AWS WAF (incl. Bot Control / CAPTCHA challenge) detector."""
from __future__ import annotations

from typing import Optional

from antibot_detect.detectors.base import Detection, Detector, make_detection, truncate
from antibot_detect.fetcher import FetchResult


class AwsWafDetector(Detector):
    name = "AWS WAF"

    _BODY_MARKERS = [
        "token.awswaf.com",
        "captcha.awswaf.com",
        "awswaf",
        "aws-waf-token",
    ]

    def detect(self, result: FetchResult) -> Optional[Detection]:
        evidence: list[str] = []
        strong = 0
        weak = 0

        if result.has_cookie("aws-waf-token"):
            evidence.append("Cookie aws-waf-token present")
            strong += 1

        server = result.header("server") or ""
        if "awselb" in server.lower():
            evidence.append(f"Header server: {truncate(server)} (AWS ELB)")
            weak += 1

        for marker in result.find_in_body(self._BODY_MARKERS):
            if marker in {"token.awswaf.com", "captcha.awswaf.com"}:
                evidence.append(f"Body marker: {marker}")
                strong += 1
            else:
                evidence.append(f"Body marker: {marker!r}")
                weak += 1

        return make_detection(self.name, evidence, strong=strong, weak=weak)
