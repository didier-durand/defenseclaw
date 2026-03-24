"""Scanner protocol — all scanners implement this interface."""

from __future__ import annotations

from typing import Protocol

from defenseclaw.models import ScanResult


class Scanner(Protocol):
    def name(self) -> str: ...
    def scan(self, target: str) -> ScanResult: ...
