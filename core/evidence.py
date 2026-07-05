"""Helpers for recording evidence metadata without retaining raw responses."""

from __future__ import annotations

import hashlib


def captured_response_sha256(*chunks: bytes) -> str:
    captured = b"".join(chunk for chunk in chunks if chunk)
    return hashlib.sha256(captured).hexdigest() if captured else ""
