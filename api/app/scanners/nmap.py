"""Genuine local Nmap execution. Only runs when `nmap` is on PATH and the
assessment is approved + scope-validated. Returns (xml_text, command, stderr).
"""
import shutil
import subprocess

from ..scope import parse_target


def available() -> bool:
    return shutil.which("nmap") is not None


def run(target: str, top_ports: int = 100, timeout: int = 180) -> dict:
    """Run a conservative Nmap scan and return XML output."""
    host = parse_target(target)
    if not available():
        return {"ok": False, "error": "nmap is not installed on this system. Install Nmap and ensure it is on PATH, or use Import-only mode.",
                "command": "", "stdout": "", "stderr": ""}
    import os
    from .. import config
    is_unprivileged = getattr(os, "geteuid", lambda: 1000)() != 0 or config.CLOUD_MODE
    cmd = ["nmap"]
    if is_unprivileged:
        cmd.extend(["-sT", "--unprivileged"])
    cmd.extend(["-sV", "-Pn", "--top-ports", str(min(top_ports, 1000)), "-oX", "-", host])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode in (0, 1), "command": " ".join(cmd), "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Nmap scan timed out.", "command": " ".join(cmd), "stdout": "", "stderr": ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "command": " ".join(cmd), "stdout": "", "stderr": ""}
