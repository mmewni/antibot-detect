from __future__ import annotations

from antibot_detect.core import run_detectors
from antibot_detect.detectors.base import Confidence

from tests.conftest import make_result


def test_run_detectors_sorts_and_partitions():
    result = make_result(
        headers={"CF-RAY": "abc-LHR", "Server": "cloudflare"},
        body='<script src="https://www.google.com/recaptcha/api.js"></script>',
    )
    detections, notDetected = run_detectors(result)

    names = {d.name for d in detections}
    assert "Cloudflare" in names
    assert "reCAPTCHA" in names

    assert "DataDome" in notDetected
    assert names.isdisjoint(set(notDetected))
    assert len(detections) + len(notDetected) >= 10


def test_run_detectors_sorted_high_first():
    result = make_result(
        headers={"CF-RAY": "abc-LHR"},
        cookies={"bm_sv": "z"},
    )
    detections, _ = run_detectors(result)
    ranks = [d.confidence.rank for d in detections]
    assert ranks == sorted(ranks, reverse=True)
    assert detections[0].confidence is Confidence.HIGH


def test_clean_site_detects_nothing():
    result = make_result(headers={"Server": "nginx"}, body="<html>hi</html>")
    detections, notDetected = run_detectors(result)
    assert detections == []
    assert "Cloudflare" in notDetected


def test_fetchresult_helpers():
    result = make_result(
        headers={"X-Foo": "bar", "X-Datadome-Cid": "123"},
        cookies={"_pxhd": "a", "datadome": "b"},
        body="Hello WORLD",
    )
    assert result.header("x-foo") == "bar"
    assert result.header("missing") is None
    assert [n for n, _ in result.headers_with_prefix("x-datadome")] == ["X-Datadome-Cid"]
    assert result.has_cookie("datadome")
    assert result.cookies_with_prefix("_px") == ["_pxhd"]
    assert result.find_in_body(["world", "nope"]) == ["world"]
