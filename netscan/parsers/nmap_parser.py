"""Parses nmap XML output (-oX) into structured ScanResult objects."""
import xml.etree.ElementTree as ET

from netscan.models import Host, Port, ScanResult


def _parse_port(port_el: ET.Element) -> Port:
    state_el = port_el.find("state")
    service_el = port_el.find("service")
    return Port(
        number=int(port_el.get("portid")),
        protocol=port_el.get("protocol"),
        state=state_el.get("state") if state_el is not None else "unknown",
        service=service_el.get("name", "") if service_el is not None else "",
        product=service_el.get("product", "") if service_el is not None else "",
        version=service_el.get("version", "") if service_el is not None else "",
    )


def _parse_host(host_el: ET.Element) -> Host:
    address_el = host_el.find("address")
    status_el = host_el.find("status")
    hostnames = [h.get("name") for h in host_el.findall("hostnames/hostname")]
    ports = [_parse_port(p) for p in host_el.findall("ports/port")]
    return Host(
        ip=address_el.get("addr") if address_el is not None else "",
        hostnames=hostnames,
        status=status_el.get("state") if status_el is not None else "unknown",
        ports=ports,
    )


def parse_string(xml_text: str) -> ScanResult:
    root = ET.fromstring(xml_text)
    args = root.get("args", "")
    target = args.split()[-1] if args else ""
    hosts = [_parse_host(h) for h in root.findall("host")]
    return ScanResult(
        target=target,
        timestamp=root.get("startstr", ""),
        hosts=hosts,
    )


def parse_file(path: str) -> ScanResult:
    with open(path) as f:
        return parse_string(f.read())
