"""Central Tool Adapter Registry and Integration Health Service.

Maintains the authoritative catalog of all scanner adapters and dynamically evaluates
health, reachability, licensing, and capabilities for the Truthful Integration Matrix.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from .base import AdapterHealth, BaseAdapter, ErrorClass, ExecutionMode, ExecutionResult
from .burp_adapter import BurpAdapter
from .metasploit_adapter import MetasploitAdapter
from .nessus_adapter import NessusAdapter
from .nikto_adapter import NiktoAdapter
from .nmap_adapter import NmapAdapter
from .nuclei_adapter import NucleiAdapter
from .openvas_adapter import OpenVASAdapter
from .zap_adapter import ZapAdapter


class AdapterRegistry:
    def __init__(self):
        self._adapters: Dict[str, BaseAdapter] = {}
        # Register core adapters in specified priority
        self.register(NmapAdapter())
        self.register(ZapAdapter())
        self.register(NiktoAdapter())
        self.register(NucleiAdapter())
        self.register(NessusAdapter())
        self.register(BurpAdapter())
        self.register(OpenVASAdapter())
        self.register(MetasploitAdapter())

    def register(self, adapter: BaseAdapter):
        self._adapters[adapter.name] = adapter

    def get(self, tool_name: str) -> Optional[BaseAdapter]:
        return self._adapters.get((tool_name or "").strip().lower())

    def list_all(self) -> List[BaseAdapter]:
        return list(self._adapters.values())

    def get_integration_matrix(self) -> List[Dict[str, Any]]:
        """Evaluate real-time operational status for all adapters.

        Returns an honest, auto-generated matrix:
        - Mode: Live / Import-Only / Config-Required / Planned
        - Capabilities, license notes, assumptions, limitations
        """
        matrix = []
        for adapter in self._adapters.values():
            health = adapter.get_health()
            matrix.append({
                "tool_name": health.tool_name,
                "display_name": health.display_name,
                "category": adapter.category.value,
                "mode": health.mode.value,
                "is_available": health.is_available,
                "version": health.version,
                "endpoint_url": health.endpoint_url,
                "binary_path": health.binary_path,
                "license_type": health.license_type,
                "licensing_verified": health.licensing_verified,
                "message": health.message,
                "limitations": health.limitations,
                "assumptions": health.assumptions,
                "supported_formats": health.supported_formats,
                "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
        return matrix


# Global registry singleton
registry = AdapterRegistry()

