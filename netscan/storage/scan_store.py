"""Saves/loads ScanResult objects as JSON so scans can be compared later."""
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from netscan.models import Host, Port, ScanResult


def _safe_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", target)


def save_scan(result: ScanResult, base_dir: str = "scans") -> str:
    directory = Path(base_dir)
    directory.mkdir(parents=True, exist_ok=True)
    saved_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = directory / f"{_safe_name(result.target)}_{saved_at}.json"
    path.write_text(json.dumps(asdict(result), indent=2))
    return str(path)


def load_scan(path: str) -> ScanResult:
    data = json.loads(Path(path).read_text())
    hosts = [
        Host(
            ip=h["ip"],
            hostnames=h["hostnames"],
            status=h["status"],
            ports=[Port(**p) for p in h["ports"]],
        )
        for h in data["hosts"]
    ]
    return ScanResult(target=data["target"], timestamp=data["timestamp"], hosts=hosts)


def list_scans(target: str, base_dir: str = "scans") -> list[str]:
    """Returns saved scan paths for target, oldest first (for future compare)."""
    directory = Path(base_dir)
    if not directory.exists():
        return []
    paths = sorted(directory.glob(f"{_safe_name(target)}_*.json"))
    return [str(p) for p in paths]
