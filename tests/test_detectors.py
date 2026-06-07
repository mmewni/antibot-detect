from __future__ import annotations

from antibot_detect.detectors.akamai import AkamaiDetector
from antibot_detect.detectors.awswaf import AwsWafDetector
from antibot_detect.detectors.base import Confidence
from antibot_detect.detectors.cloudflare import CloudflareDetector
from antibot_detect.detectors.datadome import DataDomeDetector
from antibot_detect.detectors.imperva import ImpervaDetector
from antibot_detect.detectors.recaptcha import RecaptchaDetector
from antibot_detect.detectors.turnstile import TurnstileDetector
from antibot_detect.fetcher import RedirectHop

from tests.conftest import make_result


def test_cloudflare_headers_and_cookie_high():
    result = make_result(
        headers={"Server": "cloudflare", "CF-RAY": "8a3f1c2d4e5f6789-LHR"},
        cookies={"__cf_bm": "abc123"},
    )
    detection = CloudflareDetector().detect(result)
    assert detection is not None
    assert detection.name == "Cloudflare"
    assert detection.confidence is Confidence.HIGH
    assert any("cf-ray" in e.lower() for e in detection.evidence)
    assert any("__cf_bm" in e for e in detection.evidence)


def test_cloudflare_case_insensitive_header_lookup():
    result = make_result(headers={"cF-rAy": "deadbeef-AMS"})
    detection = CloudflareDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH


def test_cloudflare_challenge_body_marker():
    result = make_result(
        body="<title>Just a moment...</title>"
        '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>'
    )
    detection = CloudflareDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH


def test_cloudflare_no_match_returns_none():
    result = make_result(headers={"Server": "nginx"}, body="<html>hello</html>")
    assert CloudflareDetector().detect(result) is None


def test_akamai_abck_cookie_high():
    result = make_result(
        headers={"Server": "AkamaiGHost"},
        cookies={"_abck": "xxx", "bm_sz": "yyy"},
    )
    detection = AkamaiDetector().detect(result)
    assert detection is not None
    assert detection.name == "Akamai Bot Manager"
    assert detection.confidence is Confidence.HIGH
    assert any("_abck" in e for e in detection.evidence)


def test_akamai_single_weak_cookie_is_medium():
    result = make_result(cookies={"bm_sv": "zzz"})
    detection = AkamaiDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.MEDIUM


def test_datadome_cookie_high():
    result = make_result(cookies={"datadome": "tok"})
    detection = DataDomeDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH


def test_datadome_captcha_delivery_body():
    result = make_result(
        body='<script src="https://geo.captcha-delivery.com/captcha/"></script>'
    )
    detection = DataDomeDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH


def test_imperva_cookie_prefix_match():
    result = make_result(
        cookies={"visid_incap_1234567": "a", "incap_ses_123_1234567": "b"},
    )
    detection = ImpervaDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH
    assert any("visid_incap_1234567" in e for e in detection.evidence)


def test_awswaf_elb_only_is_medium():
    result = make_result(headers={"Server": "awselb/2.0"})
    detection = AwsWafDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.MEDIUM


def test_awswaf_token_cookie_high():
    result = make_result(cookies={"aws-waf-token": "tok"})
    detection = AwsWafDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH


def test_recaptcha_api_js_high():
    result = make_result(
        body='<script src="https://www.google.com/recaptcha/api.js"></script>'
    )
    detection = RecaptchaDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH


def test_turnstile_marker_high():
    result = make_result(
        body='<script src="https://challenges.cloudflare.com/turnstile/v0/api.js">'
        "</script>"
    )
    detection = TurnstileDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH


def test_detector_scans_redirect_chain_headers():
    hop = RedirectHop(
        url="https://example.com/",
        status=403,
        headers={"CF-RAY": "abc-LHR", "Server": "cloudflare"},
        cookies={"__cf_bm": "v"},
    )
    result = make_result(
        status=200,
        headers={"Server": "nginx"},
        redirectChain=[hop],
    )
    detection = CloudflareDetector().detect(result)
    assert detection is not None
    assert detection.confidence is Confidence.HIGH
