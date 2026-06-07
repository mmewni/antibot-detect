from __future__ import annotations

from dataclasses import dataclass, field

from antibot_detect.detectors import ALL_DETECTORS
from antibot_detect.detectors.base import Detection, Detector
from antibot_detect.fetcher import (
    DEFAULT_IMPERSONATE,
    DEFAULT_TIMEOUT,
    FetchError,
    FetchResult,
    fetch,
)

__all__ = ["AnalysisResult", "analyze", "run_detectors", "FetchError"]


@dataclass
class AnalysisResult:
    fetch: FetchResult
    detections: list[Detection] = field(default_factory=list)
    notDetected: list[str] = field(default_factory=list)

    def to_dict(self, *, includeAll: bool = False) -> dict[str, object]:
        data: dict[str, object] = {
            "requested_url": self.fetch.requestedUrl,
            "final_url": self.fetch.finalUrl,
            "status": self.fetch.status,
            "detections": [d.to_dict() for d in self.detections],
        }
        if includeAll:
            data["not_detected"] = list(self.notDetected)
        return data


def run_detectors(
    result: FetchResult,
    detectors: list[Detector] | None = None,
) -> tuple[list[Detection], list[str]]:
    detectors = detectors if detectors is not None else ALL_DETECTORS
    detections: list[Detection] = []
    notDetected: list[str] = []

    for det in detectors:
        hit = det.detect(result)
        if hit is not None:
            detections.append(hit)
        else:
            notDetected.append(det.name)

    detections.sort(key=lambda d: d.confidence.rank, reverse=True)
    return detections, notDetected


def analyze(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    impersonate: str = DEFAULT_IMPERSONATE,
    detectors: list[Detector] | None = None,
) -> AnalysisResult:
    result = fetch(url, timeout=timeout, impersonate=impersonate)
    detections, notDetected = run_detectors(result, detectors)
    return AnalysisResult(
        fetch=result,
        detections=detections,
        notDetected=notDetected,
    )
