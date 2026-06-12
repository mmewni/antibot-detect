from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from antibot_detect.fetcher import FetchResult


class Confidence(str, Enum):
    
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


@dataclass
class Detection:

    name: str
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "confidence": self.confidence.value,
            "evidence": list(self.evidence),
        }


class Detector:
    name: str = "Detector"

    def detect(self, result: "FetchResult") -> Optional[Detection]:
        raise NotImplementedError


def truncate(value: str, limit: int = 80) -> str:
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def make_detection(
    name: str,
    evidence: list[str],
    *,
    strong: int = 0,
    weak: int = 0,
    forceLow: bool = False,
) -> Optional[Detection]:
    total = strong + weak
    if total == 0 or not evidence:
        return None

    if forceLow:
        confidence = Confidence.LOW
    elif strong >= 1 or total >= 2:
        confidence = Confidence.HIGH
    elif weak == 1:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    return Detection(name=name, confidence=confidence, evidence=evidence)
