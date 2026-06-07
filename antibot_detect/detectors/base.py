from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from antibot_detect.fetcher import FetchResult


class Confidence(str, Enum):
    """How sure a detector is that a solution is present.

    Inherits from ``str`` so it serialises cleanly to JSON as ``"HIGH"`` etc.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        """Numeric ordering so results can be sorted strongest-first."""
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


@dataclass
class Detection:
    """A single positive identification produced by a :class:`Detector`."""

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
    """Base class for all detectors.

    Subclasses set :attr:`name` and implement :meth:`detect`, returning a
    :class:`Detection` when their signature matches, or ``None`` otherwise.
    """

    name: str = "Detector"

    def detect(self, result: "FetchResult") -> Optional[Detection]:
        raise NotImplementedError


def truncate(value: str, limit: int = 80) -> str:
    """Collapse whitespace and shorten a value for display in evidence lines."""
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
    """Build a :class:`Detection` from gathered evidence and signal weights.

    Confidence policy (per the project spec):
      * one or more *strong* signals -> HIGH
      * multiple signals of any kind  -> HIGH
      * exactly one *weak* signal     -> MEDIUM
      * otherwise / ambiguous         -> LOW

    Returns ``None`` when no evidence was gathered.
    """
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
