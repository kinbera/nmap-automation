"""Runs nmap as a subprocess and returns its XML output."""
import subprocess


def run_scan(
    target: str,
    ports: str | None = None,
    extra_args: list[str] | None = None,
    nmap_path: str = "nmap",
) -> str:
    """Runs `nmap -sV -oX -` against target, returns the XML output as text.

    Raises ValueError for an unsafe-looking target, RuntimeError if nmap
    is missing or exits non-zero.
    """
    if not target or target.startswith("-"):
        raise ValueError(f"refusing to scan suspicious target: {target!r}")

    cmd = [nmap_path, "-sV", "-oX", "-"]
    if ports:
        cmd += ["-p", ports]
    if extra_args:
        cmd += extra_args
    cmd.append(target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise RuntimeError(f"'{nmap_path}' not found — is nmap installed?")

    if result.returncode != 0:
        raise RuntimeError(f"nmap exited {result.returncode}: {result.stderr.strip()}")

    return result.stdout
