"""Network logs: AI services contacted, from DNS, TLS SNI and flow records.

``network.logs`` reads exported network telemetry and reports, per client
address, the AI services it contacted:

* DNS queries: Zeek ``dns.log``, Amazon Route 53 Resolver query logs, or any
  JSON/CSV with a query name and a client address;
* TLS server names: Zeek ``ssl.log`` or any record with an ``sni`` /
  ``server_name`` field;
* flows: Zeek ``conn.log`` and AWS VPC Flow Logs. A flow carries no host
  name, so it is attributed only through the same input: by Zeek ``uid`` to
  the TLS record of the same client/connection, or to the AI host that the same
  client resolved to that address. An address that also resolved to a host
  of another service (a shared CDN address) attributes nothing through DNS.
  Known non-AI or conflicting TLS evidence never falls back to DNS.

Host names are matched exactly or by a signature's declared wildcard, never by
substring, so ``www.anthropologie.com`` is not Anthropic. Only names that
match an AI signature are kept; other queries are counted, never stored.

The connector is offline: it reads files and makes no network request.
Malformed lines and unrecognised records make the scan incomplete.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.agent_behavior import (
    LOOP_MAX_GAP_SECONDS,
    LOOP_MIN_CALLS,
    host_service,
    loop_cadence,
)
from shadowscan.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    _NoDump,
    _positive_limit,
)
from shadowscan.connectors.common import finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.text import parse_timestamp

_FORMATS = {None, "auto", "zeek", "route53", "vpc-flow", "generic"}
_SUFFIXES = {".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".gz"}
# Domain signals below this weight are hints (a vendor's marketing site), not service use.
_MIN_HOST_WEIGHT = 0.3
_MAX_CLIENTS = 50_000
_MAX_PAIRS = 500_000
_MAX_HOSTS_PER_FINDING = 20
_MAX_TIMES = 1_000
_MAX_TOTAL_TIMES = 200_000
_OLLAMA_PORT = 11434
_VPC_DEFAULT_FIELDS = [
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
]
_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)*$"
)

# Field names of generic exports, in order of preference.
_QUERY_FIELDS = ("query", "qname", "query_name", "question", "domain", "dns_query")
_SNI_FIELDS = ("sni", "server_name", "tls_sni", "servername")
_CLIENT_FIELDS = (
    "client",
    "client_ip",
    "src_ip",
    "source_ip",
    "srcaddr",
    "src",
    "id.orig_h",
    "device",
    "host_ip",
)
_SERVER_FIELDS = ("dst_ip", "dest_ip", "destination_ip", "dstaddr", "server_ip", "id.resp_h", "dst")
_PORT_FIELDS = ("dst_port", "dest_port", "dstport", "id.resp_p", "port")
_TIME_FIELDS = ("ts", "timestamp", "time", "query_timestamp", "@timestamp", "start", "event_time")


@dataclass
class _Contact:
    """One client's traffic to one AI service."""

    client: str
    signature: str
    hosts: Counter = field(default_factory=Counter)
    dns_queries: int = 0
    tls_connections: int = 0
    flows: int = 0
    flows_by_dns: int = 0
    flows_by_global_dns: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first: float | None = None
    last: float | None = None
    times: list[float] = field(default_factory=list)


@dataclass
class _Pair:
    """Flows sharing client, server, port and connection UID (when available)."""

    flows: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first: float | None = None
    last: float | None = None
    times: list[float] = field(default_factory=list)


@dataclass
class _TLSIdentity:
    """Bounded service identity for a client/UID, including negative evidence."""

    server: str | None
    port: int | None
    signature: str
    ambiguous: bool = False

    def observe(self, server: str | None, port: int | None, signature: str) -> None:
        if self.signature != signature or not self.matches(server, port):
            self.ambiguous = True
        self.server = self.server or server
        self.port = self.port if self.port is not None else port

    def matches(self, server: str | None, port: int | None) -> bool:
        return (self.server is None or server is None or self.server == server) and (
            self.port is None or port is None or self.port == port
        )


class NetworkLogConnector(BaseConnector, _NoDump):
    name: ClassVar[str] = "network.logs"
    surface: ClassVar[Surface] = Surface.NETWORK
    provider: ClassVar[str | None] = "network"
    description: ClassVar[str] = (
        "AI services contacted per client address, from DNS, TLS SNI and flow logs (Zeek, Route 53 Resolver, "
        "VPC Flow Logs, generic exports)."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "input": (
            "log file or directory: Zeek dns/ssl/conn logs (TSV or JSON), Route 53 Resolver query logs, VPC "
            "Flow Logs or generic JSON/CSV DNS and SNI records"
        ),
        "format": "force the input format: zeek|route53|vpc-flow|generic (default auto, per record)",
        "label": "network or sensor name used in resource ids and as the finding account (default: network)",
        "max_records": "stop after N records (default 10,000,000)",
    }
    offline_formats: ClassVar[str] = "Zeek TSV / JSON, Route 53 Resolver JSON, VPC Flow Logs text, JSON / CSV"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.format = ctx.get("format")
        if self.format not in _FORMATS:
            raise ConnectorError("network.logs: unsupported format")
        self.label = str(ctx.get("label") or "network")
        self.max_records = _positive_limit(ctx.get("max_records", 10_000_000), "max_records")
        self._records = 0
        self._limit_reported = False
        self._host_cache: dict[str, Match | None] = {}

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError(
            "network.logs: this connector reads exported logs; set 'input' to a file or directory"
        )

    # ------------------------------------------------------------------ input
    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        budget = self._offline_budget()
        for source in self._iter_offline_files(path, budget, _SUFFIXES):
            suffix = source.suffix.lower()
            if suffix == ".csv":
                for rec in self._load_offline_file(source, budget):
                    yield from self._limited(self._normalise(rec, source.name))
                continue
            if suffix == ".json":
                text = self._read_offline_text(source, budget)
                if text is None:
                    continue
                yield from self._limited(self._json_document(text, source.name))
                continue
            yield from self._limited(self._text_lines(source, budget, suffix))

    def _limited(self, records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        for rec in records:
            if self._records >= self.max_records:
                if not self._limit_reported:
                    self.ctx.warn(f"network.logs: stopped after max_records ({self.max_records:,}) records")
                    self._limit_reported = True
                return
            self._records += 1
            yield rec

    def _json_document(self, text: str, name: str) -> Iterator[dict[str, Any]]:
        if not text.strip():
            self.ctx.error(f"network.logs: {name}: empty export; use [] for an empty JSON export")
            return
        try:
            data = strict_json_loads(text)
        except (json.JSONDecodeError, RecursionError, ValueError):
            # One JSON object per line under a .json name (Zeek's JSON writer).
            yield from self._json_rows(text.splitlines(), name)
            return
        rows = (
            data
            if isinstance(data, list)
            else data.get("records", [data])
            if isinstance(data, dict)
            else None
        )
        if not isinstance(rows, list):
            self.ctx.warn(f"network.logs: {name}: unrecognized JSON document")
            return
        for row in rows:
            yield from self._normalise(row, name)

    def _json_rows(self, lines: Iterable[str], name: str) -> Iterator[dict[str, Any]]:
        saw = False
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            saw = True
            try:
                row = strict_json_loads(line)
            except (json.JSONDecodeError, RecursionError, ValueError):
                self.ctx.warn(f"network.logs: {name}: invalid JSON at line {number}")
                continue
            yield from self._normalise(row, name)
        if not saw:
            self.ctx.error(f"network.logs: {name}: empty export")

    def _text_lines(self, source: Path, budget: Any, suffix: str) -> Iterator[dict[str, Any]]:
        lines = self._iter_bounded_lines(source, budget, compressed=suffix == ".gz")
        zeek_fields: list[str] | None = None
        zeek_path = ""
        separator = "\t"
        set_separator = ","
        vpc_fields: list[str] | None = None
        saw = False
        for number, raw in enumerate(lines, 1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            saw = True
            if line.startswith("#"):
                directive, _, value = line.partition(separator if line.startswith("#fields") else " ")
                if line.startswith("#separator"):
                    separator = _zeek_escape(line.split(" ", 1)[1]) if " " in line else "\t"
                elif line.startswith("#set_separator"):
                    set_separator = line.split(separator, 1)[1] if separator in line else ","
                elif directive == "#fields":
                    zeek_fields = value.split(separator)
                elif line.startswith("#path"):
                    zeek_path = line.split(separator, 1)[1].strip() if separator in line else ""
                continue
            if line.lstrip().startswith("{"):
                yield from self._json_rows([line], f"{source.name} line {number}")
                continue
            if zeek_fields is not None:
                values = line.split(separator)
                if len(values) != len(zeek_fields):
                    self.ctx.warn(f"network.logs: {source.name}: malformed Zeek line {number}")
                    continue
                row: dict[str, Any] = {"_path": zeek_path}
                for key, value in zip(zeek_fields, values, strict=True):
                    if value in {"-", "(empty)"}:
                        continue
                    row[key] = value.split(set_separator) if key == "answers" else value
                yield from self._normalise(row, source.name)
                continue
            tokens = line.split()
            if tokens and tokens[0] == "version" and "srcaddr" in tokens:
                vpc_fields = tokens
                continue
            fields = vpc_fields or (_VPC_DEFAULT_FIELDS if len(tokens) == 14 and tokens[0] == "2" else None)
            if fields is not None and len(tokens) == len(fields):
                yield from self._vpc_flow(dict(zip(fields, tokens, strict=True)), source.name, number)
                continue
            self.ctx.warn(f"network.logs: {source.name}: unrecognized line {number}")
        if not saw:
            self.ctx.warn(f"network.logs: {source.name}: empty log")

    # -------------------------------------------------------------- normalise
    def _normalise(self, row: Any, name: str) -> Iterator[dict[str, Any]]:
        """One input row as dns / tls / flow events; nothing for other traffic."""
        if not isinstance(row, dict):
            self.ctx.warn(f"network.logs: {name}: records must be objects")
            return
        fmt = self.format if self.format not in (None, "auto") else _detect(row)
        if fmt == "route53":
            client = _text(row.get("srcaddr"))
            query = _host(row.get("query_name"))
            answers = [
                text
                for a in row.get("answers") or []
                if isinstance(a, dict) and (text := _text(a.get("Rdata")))
            ]
            yield from self._dns(name, client, query, answers, row.get("query_timestamp"))
            return
        if fmt == "vpc-flow":
            yield from self._vpc_flow(row, name, None)
            return
        if fmt is None:
            self.ctx.warn(f"network.logs: {name}: unrecognized record")
            return
        client = _text(_first(row, _CLIENT_FIELDS))
        when = _first(row, _TIME_FIELDS)
        query = _host(_first(row, _QUERY_FIELDS))
        sni = _host(_first(row, _SNI_FIELDS))
        server = _text(_first(row, _SERVER_FIELDS))
        port = _int(_first(row, _PORT_FIELDS))
        path = str(row.get("_path") or "")
        if query is not None or path == "dns":
            raw = row.get("answers") or []
            values = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else []
            answers = [text for a in values if (text := _text(a))]
            yield from self._dns(name, client, query, answers, when)
            return
        if sni is not None or path == "ssl":
            if not client:
                self.ctx.warn(f"network.logs: {name}: TLS record without a client address")
                return
            if sni is None:
                return  # a TLS connection without SNI names nothing
            yield {
                "kind": "tls", "ts": _seconds(when), "client": client, "server": server, "port": port,
                "sni": sni, "uid": _text(_first(row, ("uid",))),
            }  # fmt: skip
            return
        if server and client:
            yield {
                "kind": "flow", "ts": _seconds(when), "client": client, "server": server, "port": port,
                "bytes_out": _int(row.get("orig_bytes") or row.get("bytes_out") or row.get("bytes")) or 0,
                "bytes_in": _int(row.get("resp_bytes") or row.get("bytes_in")) or 0,
                "uid": _text(_first(row, ("uid",))),
            }  # fmt: skip
            return
        self.ctx.warn(f"network.logs: {name}: record has no query, server name or flow endpoints")

    def _dns(
        self, name: str, client: str | None, query: str | None, answers: list[str], when: Any
    ) -> Iterator[dict[str, Any]]:
        if not client or query is None:
            self.ctx.warn(f"network.logs: {name}: DNS record without a client address or query name")
            return
        yield {
            "kind": "dns", "ts": _seconds(when), "client": client, "query": query,
            "answers": [a for a in answers if _ip(a)][:32],
        }  # fmt: skip

    def _vpc_flow(self, row: dict[str, Any], name: str, number: int | None) -> Iterator[dict[str, Any]]:
        where = f"{name} line {number}" if number else name
        # Custom exports can omit log-status, but an explicit status must be
        # valid. SKIPDATA means AWS failed to capture flows, not an idle ENI.
        raw_statuses = [row[key] for key in ("log-status", "log_status") if key in row]
        if any(not isinstance(status, str) or not status.strip() for status in raw_statuses):
            self.ctx.warn(f"network.logs: {where}: invalid VPC flow log-status")
            return
        statuses = {status.strip().upper() for status in raw_statuses}
        if len(statuses) > 1 or statuses - {"OK", "NODATA", "SKIPDATA"}:
            self.ctx.warn(f"network.logs: {where}: invalid VPC flow log-status")
            return
        status = next(iter(statuses), "OK")
        if status == "SKIPDATA":
            self.ctx.warn(f"network.logs: {where}: VPC Flow Logs SKIPDATA reports uncaptured flows")
            return
        if status == "NODATA":
            return
        if str(row.get("action") or "ACCEPT").upper() != "ACCEPT":
            return
        client, server = _text(row.get("srcaddr")), _text(row.get("dstaddr"))
        if not (_ip(client) and _ip(server)):
            self.ctx.warn(f"network.logs: {where}: malformed VPC flow record")
            return
        yield {
            "kind": "flow", "ts": _seconds(row.get("start")), "client": client, "server": server,
            "port": _int(row.get("dstport")), "bytes_out": _int(row.get("bytes")) or 0, "bytes_in": 0,
            "uid": None,
        }  # fmt: skip

    # ---------------------------------------------------------------- analyse
    def _service(self, host: str) -> Match | None:
        """The signature that names a host's AI service, or None."""
        if host in self._host_cache:
            return self._host_cache[host]
        best = host_service(m for m in self.index.match_domain(host) if m.weight >= _MIN_HOST_WEIGHT)
        if len(self._host_cache) < 100_000:
            self._host_cache[host] = best
        return best

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        contacts: dict[tuple[str, str], _Contact] = {}
        resolved: dict[tuple[str, str], set[str]] = {}  # (client, address) -> signatures it resolved to
        resolved_any: dict[str, set[str]] = {}  # address -> signatures, any client
        address_hosts: dict[str, set[tuple[str, str]]] = {}  # address -> AI (signature, host) names
        sni_by_uid: dict[tuple[str, str], _TLSIdentity] = {}
        pairs: dict[tuple[str, str, int | None, str | None], _Pair] = {}
        times_used = 0
        dropped_pairs = dropped_clients = dropped_tls = 0
        clients: set[str] = set()
        for rec in records:
            self.ctx.examined()
            kind = rec.get("kind")
            client = str(rec.get("client"))
            if client not in clients:
                if len(clients) >= _MAX_CLIENTS:
                    dropped_clients += 1
                    continue
                clients.add(client)
            ts = rec.get("ts")
            if kind in {"dns", "tls"}:
                host = str(rec.get("query") if kind == "dns" else rec.get("sni"))
                match = self._service(host)
                signature = match.signature.id if match else ""
                if kind == "dns":
                    for address in rec.get("answers") or []:
                        resolved.setdefault((client, address), set()).add(signature)
                        resolved_any.setdefault(address, set()).add(signature)
                        names = address_hosts.setdefault(address, set())
                        if match is not None and len(names) < 8:
                            names.add((signature, host))
                elif rec.get("uid"):
                    # Non-AI names must survive as negative correlation evidence:
                    # DNS must not override the known destination of this connection.
                    uid_key = (client, str(rec["uid"]))
                    identity = sni_by_uid.get(uid_key)
                    if identity is not None:
                        identity.observe(rec.get("server"), rec.get("port"), signature)
                    elif len(sni_by_uid) < _MAX_PAIRS:
                        sni_by_uid[uid_key] = _TLSIdentity(rec.get("server"), rec.get("port"), signature)
                    else:
                        dropped_tls += 1
                if match is None:
                    continue
                c = self._contact(contacts, client, match.signature.id)
                if len(c.hosts) < _MAX_HOSTS_PER_FINDING or host in c.hosts:
                    c.hosts[host] += 1
                if kind == "dns":
                    c.dns_queries += 1
                else:
                    c.tls_connections += 1
                    if ts is not None and len(c.times) < _MAX_TIMES and times_used < _MAX_TOTAL_TIMES:
                        c.times.append(ts)
                        times_used += 1
                _seen(c, ts)
                continue
            if kind == "flow":
                uid = str(rec["uid"]) if rec.get("uid") else None
                key = (client, str(rec.get("server")), rec.get("port"), uid)
                pair = pairs.get(key)
                if pair is None:
                    if len(pairs) >= _MAX_PAIRS:
                        dropped_pairs += 1
                        continue
                    pair = pairs[key] = _Pair()
                pair.flows += 1
                pair.bytes_out += int(rec.get("bytes_out") or 0)
                pair.bytes_in += int(rec.get("bytes_in") or 0)
                if ts is not None:
                    pair.first = ts if pair.first is None else min(pair.first, ts)
                    pair.last = ts if pair.last is None else max(pair.last, ts)
                    if len(pair.times) < _MAX_TIMES and times_used < _MAX_TOTAL_TIMES:
                        pair.times.append(ts)
                        times_used += 1
        if dropped_clients:
            self.ctx.warn(
                f"network.logs: {dropped_clients:,} record(s) from clients beyond the first {_MAX_CLIENTS:,} "
                "addresses were not analysed"
            )
        if dropped_pairs:
            self.ctx.warn(
                f"network.logs: {dropped_pairs:,} flow record(s) beyond {_MAX_PAIRS:,} connection groups "
                "were not attributed"
            )
        if dropped_tls:
            self.ctx.warn(
                f"network.logs: {dropped_tls:,} TLS record(s) beyond {_MAX_PAIRS:,} client/UID identities "
                "were not retained for flow attribution"
            )
        ambiguous = self._attribute_flows(
            contacts, pairs, sni_by_uid, bool(dropped_tls), resolved, resolved_any, address_hosts
        )
        if ambiguous:
            # Strict attribution, not missing coverage: the scan stays complete.
            self.ctx.warn(
                f"network.logs: {ambiguous:,} flow(s) with ambiguous service attribution were not attributed",
                incomplete=False,
            )
        for c in contacts.values():
            yield self._finding(c, ambiguous)

    @staticmethod
    def _contact(contacts: dict[tuple[str, str], _Contact], client: str, signature: str) -> _Contact:
        key = (client, signature)
        c = contacts.get(key)
        if c is None:
            c = contacts[key] = _Contact(client, signature)
        return c

    def _attribute_flows(
        self,
        contacts: dict[tuple[str, str], _Contact],
        pairs: dict[tuple[str, str, int | None, str | None], _Pair],
        sni_by_uid: dict[tuple[str, str], _TLSIdentity],
        tls_limit_reached: bool,
        resolved: dict[tuple[str, str], set[str]],
        resolved_any: dict[str, set[str]],
        address_hosts: dict[str, set[tuple[str, str]]],
    ) -> int:
        """Attribute connection groups before adding traffic to service totals."""
        # Generic SNI exports can omit endpoints. Bind those identities from
        # flows first, so a reused UID spanning endpoints cannot claim both.
        # Finish this pass before attribution to keep ambiguity order-independent.
        for client, server, port, uid in pairs:
            identity = sni_by_uid.get((client, uid)) if uid is not None else None
            if identity is not None:
                identity.observe(server, port, identity.signature)
        ambiguous = 0
        for (client, server, port, uid), pair in pairs.items():
            signature: str | None = None
            basis = ""
            identity = sni_by_uid.get((client, uid)) if uid is not None else None
            if identity is not None:
                if identity.ambiguous or not identity.matches(server, port):
                    ambiguous += pair.flows
                    continue
                if not identity.signature:
                    continue  # Known non-AI SNI cannot become AI traffic via DNS/port.
                signature, basis = identity.signature, "tls"
            elif uid is not None and tls_limit_reached:
                # A dropped SNI might contradict DNS; do not guess after overflow.
                continue
            else:
                local = resolved.get((client, server))
                anywhere = resolved_any.get(server)
                if local:
                    if len(local) == 1 and "" not in local:
                        signature, basis = next(iter(local)), "dns"
                    elif local - {""}:
                        ambiguous += pair.flows
                elif anywhere:
                    if len(anywhere) == 1 and "" not in anywhere:
                        signature, basis = next(iter(anywhere)), "global-dns"
                    elif anywhere - {""}:
                        ambiguous += pair.flows
                elif port == _OLLAMA_PORT and self.index.get("provider.ollama") is not None:
                    signature, basis = "provider.ollama", "port"
            if signature is None:
                continue
            c = self._contact(contacts, client, signature)
            if basis == "port":
                c.hosts[f"{server}:{port}"] += pair.flows
            elif basis in {"dns", "global-dns"}:
                for sig_id, name in sorted(address_hosts.get(server, ())):
                    if sig_id == signature and (len(c.hosts) < _MAX_HOSTS_PER_FINDING or name in c.hosts):
                        c.hosts[name] += pair.flows
            c.flows += pair.flows
            c.flows_by_dns += pair.flows if basis == "dns" else 0
            c.flows_by_global_dns += pair.flows if basis == "global-dns" else 0
            c.bytes_out += pair.bytes_out
            c.bytes_in += pair.bytes_in
            if basis != "tls":
                # A TLS-linked flow is the same connection as its SNI record.
                room = _MAX_TIMES - len(c.times)
                c.times.extend(pair.times[: max(0, room)])
            _seen(c, pair.first)
            _seen(c, pair.last)
        return ambiguous

    def _finding(self, c: _Contact, ambiguous: int) -> Finding:
        sig = self.index.get(c.signature)
        product = sig.name if sig else c.signature
        hosts = [h for h, _ in c.hosts.most_common(5)]
        f = Finding(
            surface=Surface.NETWORK,
            connector=self.name,
            kind=Kind.NETWORK_CONTACT,
            title=f"AI service contacted: {product} ({', '.join(hosts[:2]) or 'by address'}) from {c.client}",
            resource=f"network:{self.label}:{c.client}:{c.signature}",
            resource_type="network-contact",
            provider="network",
            account=self.label,
            first_seen=_iso(c.first),
            last_seen=_iso(c.last),
        )
        if sig is not None:
            if sig.category == "provider":
                f.add_model_provider(sig.id)
            else:
                f.add_framework(sig.id)
            for capability in sig.capabilities:
                f.add_capability(capability)
            for tag in sig.tags:
                f.add_tag(tag)
        if c.dns_queries:
            f.add_evidence(
                Evidence(
                    signal="network:dns",
                    description=f"{c.dns_queries} DNS quer(ies) for {', '.join(hosts)}",
                    weight=0.5,
                    signature=c.signature,
                )
            )
        if c.tls_connections:
            f.add_evidence(
                Evidence(
                    signal="network:tls-sni",
                    description=f"{c.tls_connections} TLS connection(s) naming {', '.join(hosts)}",
                    weight=0.7,
                    signature=c.signature,
                )
            )
        if c.flows:
            basis = []
            if c.flows_by_dns:
                basis.append(f"{c.flows_by_dns} by this client's DNS answers")
            if c.flows_by_global_dns:
                basis.append(f"{c.flows_by_global_dns} by another client's DNS answers")
            rest = c.flows - c.flows_by_dns - c.flows_by_global_dns
            if rest:
                basis.append(f"{rest} by TLS server name or service port")
            f.add_evidence(
                Evidence(
                    signal="network:flow",
                    description=(
                        f"{c.flows} flow(s), {c.bytes_out:,} bytes sent, {c.bytes_in:,} received; attributed "
                        + "; ".join(basis)
                    ),
                    weight=0.4 if c.flows_by_global_dns == c.flows else 0.6,
                    signature=c.signature,
                )
            )
        if sig is not None and sig.agent_indicator and sig.category != "identity-app":
            # A coding agent's, MCP server's or agent platform's own service.
            f.metadata["agent_indicators"] = 1
            f.add_tag("agent-service")
        cadence = loop_cadence(c.times)
        if cadence.loops and sig is not None and sig.category == "provider":
            # Browsers rarely open connections to a model API; scripts and agents do.
            f.add_tag("agent-loop")
            f.add_evidence(
                Evidence(
                    signal="network:agent-loop",
                    description=(
                        f"{cadence.loops} run(s) of {LOOP_MIN_CALLS}+ connections at most "
                        f"{LOOP_MAX_GAP_SECONDS:.0f}s apart (longest {cadence.longest}): agent-loop cadence; "
                        "a batch script looks the same, and connection reuse hides requests"
                    ),
                    weight=0.4,
                )
            )
            f.metadata["agent_indicators"] = f.metadata.get("agent_indicators", 0) + 1
        f.metadata.update(
            {
                "client": c.client,
                "service": c.signature,
                "hosts": dict(c.hosts.most_common(_MAX_HOSTS_PER_FINDING)),
                "dns_queries": c.dns_queries,
                "tls_connections": c.tls_connections,
                "flows": c.flows,
                "bytes_out": c.bytes_out,
                "bytes_in": c.bytes_in,
                "network": self.label,
            }
        )
        if cadence.loops:
            f.metadata["loop_cadence"] = {"loops": cadence.loops, "longest": cadence.longest}
        if ambiguous:
            f.metadata["ambiguous_flows_in_input"] = ambiguous
        return finalize(f, self.index)


# ------------------------------------------------------------------- helpers


def _detect(row: dict[str, Any]) -> str | None:
    if "query_name" in row and "srcaddr" in row:
        return "route53"
    if "log-status" in row or "log_status" in row or {"srcaddr", "dstaddr", "dstport"} <= row.keys():
        return "vpc-flow"
    if "id.orig_h" in row or "_path" in row:
        return "zeek"
    keys = set(row)
    if keys & set(_QUERY_FIELDS + _SNI_FIELDS) or (keys & set(_CLIENT_FIELDS) and keys & set(_SERVER_FIELDS)):
        return "generic"
    return None


def _first(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, "", "-"):
            return value
    return None


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = str(value).strip()
    return text[:255] or None


def _host(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    host = text.lower().rstrip(".")
    return host if _HOST.match(host) and not _ip(host) else None


def _ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 10**15 else None


def _seconds(value: Any) -> float | None:
    moment = parse_timestamp(value)
    return moment.timestamp() if moment else None


def _iso(value: float | None) -> str | None:
    if value is None:
        return None
    moment = parse_timestamp(value)
    return moment.isoformat() if moment else None


def _seen(c: _Contact, ts: float | None) -> None:
    if ts is None:
        return
    c.first = ts if c.first is None else min(c.first, ts)
    c.last = ts if c.last is None else max(c.last, ts)


def _zeek_escape(text: str) -> str:
    """Decode a Zeek ``#separator`` value such as ``\\x09``."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text.strip())
