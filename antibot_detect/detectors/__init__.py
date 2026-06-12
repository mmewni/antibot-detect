from __future__ import annotations

from antibot_detect.detectors.akamai import AkamaiDetector
from antibot_detect.detectors.awswaf import AwsWafDetector
from antibot_detect.detectors.base import Confidence, Detection, Detector
from antibot_detect.detectors.cloudflare import CloudflareDetector
from antibot_detect.detectors.datadome import DataDomeDetector
from antibot_detect.detectors.hcaptcha import HcaptchaDetector
from antibot_detect.detectors.imperva import ImpervaDetector
from antibot_detect.detectors.kasada import KasadaDetector
from antibot_detect.detectors.perimeterx import PerimeterXDetector
from antibot_detect.detectors.recaptcha import RecaptchaDetector
from antibot_detect.detectors.turnstile import TurnstileDetector

ALL_DETECTORS: list[Detector] = [
    CloudflareDetector(),
    AkamaiDetector(),
    DataDomeDetector(),
    PerimeterXDetector(),
    ImpervaDetector(),
    KasadaDetector(),
    AwsWafDetector(),
    RecaptchaDetector(),
    HcaptchaDetector(),
    TurnstileDetector(),
]

__all__ = [
    "ALL_DETECTORS",
    "Confidence",
    "Detection",
    "Detector",
    "AkamaiDetector",
    "AwsWafDetector",
    "CloudflareDetector",
    "DataDomeDetector",
    "HcaptchaDetector",
    "ImpervaDetector",
    "KasadaDetector",
    "PerimeterXDetector",
    "RecaptchaDetector",
    "TurnstileDetector",
]
