"""Renders a single scan result as a terminal report."""
import sys

from netscan.models import ScanResult

BOLD = "\033[1m"
GREEN = "\033[92m"
RESET = "\033[0m"


def _colors_enabled() -> bool:
    return sys.stdout.isatty()


def render(result: ScanResult) -> None:
    use_color = _colors_enabled()
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""

    print(f"{bold}== Scan report: {result.target} =={reset}")
    print(f"  Scanned at: {result.timestamp}")

    if not result.hosts:
        print("  No hosts found.\n")
        return

    for host in result.hosts:
        names = f" ({', '.join(host.hostnames)})" if host.hostnames else ""
        print(f"\n{bold}Host{reset} {host.ip}{names} — {host.status}")

        open_ports = [p for p in host.ports if p.state == "open"]
        if not open_ports:
            print("  No open ports.")
            continue

        print(f"  {'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION'}")
        for port in sorted(open_ports, key=lambda p: p.number):
            color = GREEN if use_color else ""
            version = f"{port.product} {port.version}".strip()
            port_str = f"{port.number}/{port.protocol}"
            print(f"  {color}{port_str:<10}{port.state:<10}{reset}{port.service:<15}{version}")
    print()
