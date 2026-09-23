"""Signature-driven detection.

Signatures are YAML documents (see ``shadowscan/signatures/data``) describing
*how a framework, model provider, protocol, platform or product manifests
itself* on the different surfaces ShadowScan scans: dependency names, import
statements, code idioms, config files, env vars, domains, user agents,
container images, IaC resource types, OAuth scopes, model ids, secret formats
and display names.

Connectors never hard-code product knowledge; they ask the
:class:`SignatureIndex` what a given observation means.
"""

from shadowscan.signatures.loader import Signal, Signature, load_signatures
from shadowscan.signatures.matcher import Match, SignatureIndex, get_index

__all__ = ["Signal", "Signature", "load_signatures", "Match", "SignatureIndex", "get_index"]
