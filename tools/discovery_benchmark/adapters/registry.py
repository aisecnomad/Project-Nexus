"""All adapters, in report order."""

from __future__ import annotations

from tools.discovery_benchmark.adapters import Adapter
from tools.discovery_benchmark.adapters.agentdiscover import AgentDiscoverAdapter
from tools.discovery_benchmark.adapters.agentic_radar import AgenticRadarAdapter
from tools.discovery_benchmark.adapters.cdxgen import CdxgenAdapter
from tools.discovery_benchmark.adapters.cisco_aibom import CiscoAibomAdapter
from tools.discovery_benchmark.adapters.geiger import GeigerAdapter
from tools.discovery_benchmark.adapters.nuguard import NuGuardAdapter
from tools.discovery_benchmark.adapters.shadowscan import ShadowScanAdapter
from tools.discovery_benchmark.adapters.trusera_ai_bom import TruseraAdapter
from tools.discovery_benchmark.adapters.vet import VetAdapter
from tools.discovery_benchmark.adapters.xbom import XbomAdapter


def all_adapters() -> list[Adapter]:
    return [
        ShadowScanAdapter(),
        TruseraAdapter(),
        NuGuardAdapter(),
        AgentDiscoverAdapter(),
        AgenticRadarAdapter(),
        XbomAdapter(),
        VetAdapter(),
        GeigerAdapter(),
        CdxgenAdapter(),
        CiscoAibomAdapter(),
    ]


def adapters_by_id() -> dict[str, Adapter]:
    return {adapter.spec.id: adapter for adapter in all_adapters()}
