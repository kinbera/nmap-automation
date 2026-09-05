"""Common interface all comparison rules must implement."""
from dataclasses import dataclass

from netscan.models import ScanResult


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    host: str
    port: int | None = None


class Rule:
    name = "base"

    def compare(self, baseline: ScanResult, current: ScanResult) -> list[Finding]:
        """Compares a baseline scan against a newer one, returns findings."""
        raise NotImplementedError
