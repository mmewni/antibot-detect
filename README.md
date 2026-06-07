# antibot-detect

**Identify which anti-bot / bot-management solution a website uses (detection only).**

`antibot-detect` performs *passive* fingerprinting: it makes a single, ordinary
browser-like request to a URL and inspects the response **headers, cookies, and
HTML body** for the common signatures of well-known bot-management products. It
then reports what it found, with a confidence level and the exact evidence that
matched.

It uses [`curl_cffi`](https://github.com/yifeikong/curl_cffi) to impersonate a
real Chrome browser at the TLS layer, so it can reach pages that would otherwise
reject a generic HTTP client on fingerprint alone.

> It does **not** solve challenges, defeat protections, or evade detection. It
> only tells you *what is there*.

---

## Detected providers

| Provider | Signals used |
| --- | --- |
| **Cloudflare** | `cf-ray`, `cf-cache-status`, `server: cloudflare` headers; `__cf_bm`, `cf_clearance` cookies; `/cdn-cgi/challenge-platform/`, "Just a moment…", "Checking your browser" body markers |
| **Akamai Bot Manager** | `AkamaiGHost` server header, `X-Akamai-*` headers; `_abck`, `bm_sz`, `bm_sv`, `ak_bmsc` cookies |
| **DataDome** | `datadome` cookie; `x-datadome*` headers; `geo.captcha-delivery.com` references |
| **PerimeterX / HUMAN** | `_px`, `_pxhd`, `_pxvid` cookies; `/api/v1/px/`, `client.perimeterx.net`, `px-captcha` body markers |
| **Imperva / Incapsula** | `incap_ses_*`, `visid_incap_*`, `nlbi_*` cookies; `X-Iinfo`, `X-CDN: Incapsula` headers |
| **Kasada** | `x-kpsdk-ct`, `x-kpsdk-v` headers; `ips.js` script reference |
| **AWS WAF** | `aws-waf-token` cookie; `awselb/` server header; AWS WAF challenge markers |
| **reCAPTCHA** | `google.com/recaptcha/api.js`, `gstatic.com/recaptcha/` |
| **hCaptcha** | `hcaptcha.com/1/api.js`, `js.hcaptcha.com` |
| **Cloudflare Turnstile** | `challenges.cloudflare.com/turnstile/` |

Confidence is scored as:

- **HIGH** — one strong signal (e.g. a vendor-specific cookie or header) or two
  or more signals of any kind.
- **MEDIUM** — a single weak/ambiguous signal.
- **LOW** — present but inconclusive.

---

## Install

Requires **Python 3.10+**.

```bash
git clone https://github.com/mmewni/antibot-detect.git
cd antibot-detect

# a virtual environment
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate

# editable install
pip install -e .

# with test dependencies
pip install -e ".[dev]"
```

---

## Usage

```text
antibot-detect <url> [--json] [--all] [--timeout SECS] [--verbose]
```

| Option | Description |
| --- | --- |
| `--json` | Machine-readable JSON output (to stdout). |
| `--all` | Also list detectors that did **not** match. |
| `--timeout SECS` | Request timeout in seconds (default: 15). |
| `--verbose` | Show fetch details: status, redirect chain, sampled headers, cookies. |
| `-V`, `--version` | Print the version. |
| `-h`, `--help` | Show help. |

### Example: a Cloudflare-fronted site

```bash
$ antibot-detect https://www.cloudflare.com
            Detected bot-management / anti-bot solutions
┏━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Solution   ┃ Confidence ┃ Evidence                                  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Cloudflare │ HIGH       │ Header cf-ray: a07db3657c5b438f-LHR       │
│            │            │ Header server: cloudflare                 │
│            │            │ Cookie __cf_bm present                    │
└────────────┴────────────┴───────────────────────────────────────────┘
```

### Example: JSON output

```bash
$ antibot-detect https://www.cloudflare.com --json
{
  "requested_url": "https://www.cloudflare.com",
  "final_url": "https://www.cloudflare.com/",
  "status": 200,
  "detections": [
    {
      "name": "Cloudflare",
      "confidence": "HIGH",
      "evidence": [
        "Header cf-ray: a07db368eaa2ae03-LHR",
        "Header server: cloudflare",
        "Cookie __cf_bm present (Bot Management)"
      ]
    }
  ],
  "tool": "antibot-detect",
  "version": "0.1.0"
}
```

### Example: nothing detected, listing all detectors

```bash
$ antibot-detect https://example.org --all
╭──────────────────────────────── Result ─────────────────────────────────╮
│ No known anti-bot / bot-management solution detected via passive        │
│ fingerprinting.                                                         │
│ Note: a negative result is not proof of absence; JS-only defenses may   │
│ not be visible without rendering.                                       │
╰─────────────────────────────────────────────────────────────────────────╯

Not detected: Cloudflare, Akamai Bot Manager, DataDome, PerimeterX / HUMAN,
Imperva / Incapsula, Kasada, AWS WAF, reCAPTCHA, hCaptcha, Cloudflare Turnstile
```

### Use as a library

```python
from antibot_detect.core import analyze

result = analyze("https://example.com", timeout=15)
for detection in result.detections:
    print(detection.name, detection.confidence, detection.evidence)
```

---

## How it works

1. **Fetch** (`fetcher.py`) — `curl_cffi` requests the URL while impersonating
   `chrome120`, sending a realistic header set (`Accept`, `Accept-Language`,
   `Sec-Fetch-*`, etc.). The `User-Agent` is *not* set manually so it stays
   consistent with the impersonated TLS fingerprint. Redirects are followed and
   every hop's status, headers, and cookies are recorded. The body is captured
   up to ~500 KB.
2. **Detect** (`detectors/`) — each detector scans the headers (case-insensitive,
   across the full redirect chain), cookies, and body for its provider's
   signatures, and returns a `Detection` with evidence and a confidence score.
3. **Report** (`cli.py`) — results are rendered as a `rich` table, or as JSON.

---

## Future Additions

- **`--browser` mode** — an optional Playwright-backed fetch that executes
  JavaScript, so detectors can also see dynamically injected challenge widgets
  and scripts that never appear in the raw HTML (many CAPTCHA and sensor scripts
  are added at runtime).
- Support for more anti-bot/WAF providers
- A `--batch` mode that reads a list of URLs from a file.
- Per-signal weighting tunable via a config file.

---

## Disclaimer

> This tool is for **defensive security research, web development, and
> educational purposes**. It only identifies bot-management solutions via
> passive fingerprinting — it does **not** attempt to bypass them.

---

## License

[MIT](LICENSE)
