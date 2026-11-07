"""Genuine local Nikto execution (when installed & authorized)."""
import shutil
import subprocess

from ..scope import parse_target


def available() -> bool:
    return shutil.which("nikto") is not None


def run(target: str, timeout: int = 180) -> dict:
    """Run Nikto against http(s)://host and return text output."""
    host = parse_target(target)
    url = f"http://{host}"
    if not available():
        return {"ok": False, "error": "nikto is not installed on this system. Install Nikto (or use a container) or use Import-only mode.",
                "command": "", "stdout": "", "stderr": ""}
    cmd = ["nikto", "-host", url, "-ask", "no", "-output", "-", "-Format", "txt"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": True, "command": " ".join(cmd), "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Nikto scan timed out.", "command": " ".join(cmd), "stdout": "", "stderr": ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "command": " ".join(cmd), "stdout": "", "stderr": ""}
