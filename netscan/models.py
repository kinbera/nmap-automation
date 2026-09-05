"""Data structures shared by the parser, rules, and dashboard."""
from dataclasses import dataclass, field


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""


@dataclass
class Host:
    ip: str
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    ports: list[Port] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    timestamp: str
    hosts: list[Host] = field(default_factory=list)
