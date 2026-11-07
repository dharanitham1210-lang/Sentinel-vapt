"""Common Tool Adapter Interface and Abstraction Layer.

Non-Negotiable Integration Rules:
1. Every adapter declares its true operational capability: LIVE, IMPORT_ONLY, PLANNED, or CONFIG_REQUIRED.
2. No commercial tool is claimed as 'LIVE' without an active, verified, licensed API endpoint or binary.
3. Every live execution passes through the Scope Gate prior to process launch.
4. Commands are built as argument arrays (NO shell string concatenation), preventing command injection.
5. All executions generate raw tool artifacts stored with SHA-256 verification and line/byte offsets.
"""

from __future__ import annotations

import abc
import datetime
import enum
import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class ExecutionMode(str, enum.Enum):
    LIVE = "live"
    IMPORT_ONLY = "import_only"
    CONFIG_REQUIRED = "config_required"
    PLANNED = "planned"


class ToolCategory(str, enum.Enum):
    NETWORK_DISCOVERY = "Network Discovery & Port Scanning"
    WEB_APP_SCANNER = "Web Application Vulnerability Scanner"
    INFRASTRUCTURE_VULN = "Host & Infrastructure Vulnerability Scanner"
    OFFENSIVE_VALIDATION = "Offensive Validation & Exploitation"
    RECON_ASSET_DISCOVERY = "Reconnaissance & Asset Discovery"


class ErrorClass(str, enum.Enum):
    SCOPE_VIOLATION = "scope_violation"
    APPROVAL_REQUIRED = "approval_required"
    BINARY_MISSING = "binary_missing"
    AUTH_FAILED = "auth_failed"
    TIMEOUT = "timeout"
    NETWORK_UNREACHABLE = "network_unreachable"
    EXECUTION_ERROR = "execution_error"
    PARSE_ERROR = "parse_error"


@dataclass
class AdapterHealth:
    tool_name: str
    display_name: str
    mode: ExecutionMode
    is_available: bool
    version: Optional[str] = None
    binary_path: Optional[str] = None
    endpoint_url: Optional[str] = None
    license_type: str = "Open Source"
    licensing_verified: bool = True
    message: str = "Ready"
    limitations: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    supported_formats: List[str] = field(default_factory=list)


@dataclass
class ExecutionResult:
    tool_name: str
    target: str
    ok: bool
    status: str  # queued, running, succeeded, failed, timeout, cancelled
    command: List[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    error_class: Optional[ErrorClass] = None
    error_message: Optional[str] = None
    artifact_raw: bytes = b""
    artifact_sha256: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)


class BaseAdapter(abc.ABC):
    """Abstract Base Class for all SentinelVAPT Tool Adapters."""

    def __init__(self, name: str, display_name: str, category: ToolCategory):
        self.name = name.lower()
        self.display_name = display_name
        self.category = category

    @abc.abstractmethod
    def get_health(self) -> AdapterHealth:
        """Dynamically probe local environment or remote API to determine true availability."""
        pass

    @abc.abstractmethod
    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Construct deterministic argument array without shell expansion."""
        pass

    @abc.abstractmethod
    def parse_output(self, raw_data: bytes | str, filename: str = "", sha256: str = "") -> List[Dict[str, Any]]:
        """Normalize raw scanner artifacts into the unified finding schema."""
        pass

    def run_subprocess(
        self,
        cmd: List[str],
        timeout: int = 180,
    ) -> Tuple[bool, str, str, int, Optional[ErrorClass], Optional[str]]:
        """Execute a hardened subprocess with argument arrays, non-shell execution, and timeout enforcement."""
        try:
            start = datetime.datetime.now()
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            # Some tools (e.g. Nmap, Nikto) exit with code 1 if issues are discovered
            ok = proc.returncode in (0, 1)
            err_cls = None if ok else ErrorClass.EXECUTION_ERROR
            err_msg = None if ok else (proc.stderr or f"Process exited with code {proc.returncode}")
            return ok, proc.stdout, proc.stderr, proc.returncode, err_cls, err_msg
        except subprocess.TimeoutExpired:
            return False, "", "Execution timed out.", -1, ErrorClass.TIMEOUT, f"Command timed out after {timeout} seconds."
        except FileNotFoundError:
            return False, "", "Executable not found.", -1, ErrorClass.BINARY_MISSING, f"Binary '{cmd[0]}' not found on system PATH."
        except Exception as e:
            return False, "", str(e), -1, ErrorClass.EXECUTION_ERROR, str(e)

