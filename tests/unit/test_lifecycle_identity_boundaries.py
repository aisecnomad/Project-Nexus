"""Runtime corroboration requires the full device identity and fresh derived state."""

from __future__ import annotations

import pytest

from shadowscan.correlation import correlate_lifecycle
from shadowscan.models import Finding, Kind, Surface
from shadowscan.utils.redaction import REDACTED


def _findings(endpoint_device, runtime_device):
    endpoint = Finding(
        surface=Surface.ENDPOINT,
        connector="endpoint.inventory",
        kind=Kind.AI_APP,
        title="Installed Claude Code",
        resource=f"endpoint:{endpoint_device}:claude",
        resource_type="ai-app",
        account=endpoint_device,
        frameworks=["coding-agent.claude-code"],
    )
    process = Finding(
        surface=Surface.RUNTIME,
        connector="runtime.processes",
        kind=Kind.RUNTIME_PROCESS,
        title="Running Claude Code",
        resource=f"runtime:{runtime_device}:claude:1",
        resource_type="process",
        account=runtime_device,
        frameworks=["coding-agent.claude-code"],
        tags=["observed-running"],
    )
    return endpoint, process


@pytest.mark.parametrize(
    "runtime_device",
    ["build-01.prod.example.com", "build-01", "build-01.dev.example.net"],
)
def test_same_short_host_does_not_establish_device_identity(runtime_device):
    endpoint, process = _findings("build-01.dev.example.com", runtime_device)
    correlate_lifecycle([endpoint, process])
    assert "observed-running" not in endpoint.tags
    assert "lifecycle" not in endpoint.metadata
    assert not endpoint.evidence
    assert "observed-running" in process.tags


@pytest.mark.parametrize(
    "device", [REDACTED, REDACTED.lower(), "build-[REDACTED].example.com", "[ReDaCtEd]-device"]
)
def test_identical_redacted_device_values_do_not_establish_identity(device):
    endpoint, process = _findings(device, device)
    correlate_lifecycle([endpoint, process])
    assert "observed-running" not in endpoint.tags
    assert "lifecycle" not in endpoint.metadata
    assert "lifecycle" not in process.metadata
    assert not endpoint.evidence
    assert "observed-running" in process.tags


@pytest.mark.parametrize(
    "endpoint_device,runtime_device",
    [
        ("build-01", "build-01"),
        ("build-01.dev.example.com", "BUILD-01.DEV.EXAMPLE.COM"),
        ("device-8f035a42", "device-8f035a42"),
    ],
)
def test_exact_full_device_identity_establishes_runtime_corroboration(endpoint_device, runtime_device):
    endpoint, process = _findings(endpoint_device, runtime_device)
    correlate_lifecycle([endpoint, process])
    assert "observed-running" in endpoint.tags
    assert endpoint.metadata["lifecycle"]["states"] == ["installed", "running"]
    assert any(e.signal == "lifecycle:observed-running" for e in endpoint.evidence)


def test_repeated_pass_removes_endpoint_derived_runtime_tag():
    endpoint, process = _findings("build-01.dev.example.com", "build-01.dev.example.com")
    endpoint.add_tag("installed")
    correlate_lifecycle([endpoint, process])
    assert "observed-running" in endpoint.tags
    correlate_lifecycle([endpoint])
    assert endpoint.tags == ["installed"]
    assert "lifecycle" not in endpoint.metadata
    assert not any(e.signal == "lifecycle:observed-running" for e in endpoint.evidence)
    correlate_lifecycle([process])
    assert process.tags == ["observed-running"]
