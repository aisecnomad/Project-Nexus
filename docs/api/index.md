# API Reference

Auto-generated reference for the ShadowScan Python API.

These pages are built from source docstrings using
[mkdocstrings](https://mkdocstrings.github.io/).

## Core Modules

| Module | Description |
|--------|-------------|
| [Engine](engine.md) | Scan orchestration and concurrent connector execution |
| [Models](models.md) | Finding, Evidence, ScanResult and supporting data types |
| [Config](config.md) | Scan configuration parsing and validation |
| [Risk](risk.md) | Risk scoring and policy |
| [Merge](merge.md) | Finding deduplication and merge logic |
| [Correlation](correlation.md) | Cross-surface finding correlation |

## Connector Framework

| Module | Description |
|--------|-------------|
| [Base connector](base.md) | ABC for all connectors |
| [Registry](registry.md) | Inventory reconciliation |

## Utilities

| Module | Description |
|--------|-------------|
| [HTTP client](http.md) | SSRF-safe HTTP transport |
| [Redaction](redaction.md) | Credential sanitization |
