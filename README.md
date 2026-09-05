# nmap-automation

A Python tool that automates nmap scanning and detects changes between scans —
newly opened ports, service or version changes.

I built this alongside my SIEM log simulator, using the same core loop
(scan/generate → parse → apply rules → report), but here the data source is
live network scanning instead of log files.

## What it does

- Runs `nmap -sV` against a target and parses the XML output into structured
  data (host, port, service, version)
- Saves each scan as a timestamped JSON file
- Compares the two most recent scans for a target and flags:
  - newly opened ports
  - service version changes on an existing port
- Shows a summary + detailed report in the terminal

## Usage

```bash
# Run a scan and save it
python main.py scan <target> --ports <ports> --out scans/

# Example
python main.py scan 192.168.122.1 --ports 22,53 --out scans/

# Compare the two most recent scans for a target
python main.py compare <target>
```

If `nmap` isn't installed, `scan` fails with a clear error instead of a raw
traceback.

## Rules

- `new_open_port` (MEDIUM, or HIGH — see Threat intel enrichment below) — a
  port that was closed in the baseline scan is open in the current one
- `new_service_version` (LOW) — the service name is unchanged but the
  detected version differs between scans

A change in service name itself (e.g. http → rtsp on the same port) is treated
as a separate case, not a version change.

## Threat intel enrichment

`new_open_port` can optionally cross-check the host's IP against a local IOC
database built by the sibling [threat-intel-aggregator](../threat-intel-aggregator)
project (abuse.ch URLhaus/ThreatFox feeds). If the IP is a known-bad IOC, the
finding's severity escalates from `medium` to `high`. This is an
editable-install dependency, not a copy-pasted function — both projects stay
independent repos.

Setup (system Python here is externally managed, so a venv is required):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Point `new_open_port` at the other project's SQLite store via the
`THREAT_INTEL_DB` environment variable:

```bash
export THREAT_INTEL_DB=/absolute/path/to/threat-intel-aggregator/data/iocs.db
python main.py compare 192.168.122.1
```

If `THREAT_INTEL_DB` is unset, `new_open_port` never opens a threat-intel
connection at all — it works exactly as before, findings just stay `medium`.

## Project structure

- `netscan/runner/` — runs nmap as a subprocess, returns raw XML
- `netscan/parsers/` — turns nmap XML into `Host` / `Port` / `ScanResult` objects
- `netscan/storage/` — saves/loads scans as timestamped JSON files
- `netscan/rules/` — compares two `ScanResult`s and produces findings
- `netscan/dashboard/` — renders scan reports and diff reports in the terminal
- `tests/` — run with `python -m unittest discover -s tests`

## Tests

```bash
python -m unittest discover -s tests -v
```

25 tests, covering the parser, runner (mocked subprocess calls), storage,
rules (including threat-intel severity escalation), and both CLI commands.
The threat-intel tests use an in-memory threat-intel-aggregator store, so
`python -m unittest discover -s tests` works whether or not `THREAT_INTEL_DB`
is set.

## Notes

Target validation rejects anything starting with `-` to prevent it from being
interpreted as an nmap flag. Scans were validated end-to-end against a live
target (localhost / a local VM network) — see the rule test cases for the
boundary behavior (unchanged port produces no finding, a genuinely new port
does).
