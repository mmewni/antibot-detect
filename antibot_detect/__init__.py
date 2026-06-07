"""antibot-detect: passively fingerprint a website's anti-bot / bot-management stack.

Detection only. This package never attempts to bypass, defeat, or evade any
protection mechanism — it merely identifies which solution (if any) is present
based on response headers, cookies, and body markers.
"""
from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
