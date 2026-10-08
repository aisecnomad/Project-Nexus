# Network connector

The network connector finds AI services contacted from your network in DNS,
TLS and flow telemetry that you already collect. It covers traffic that never
passes an AI gateway or an HTTP proxy: a laptop resolving `api.anthropic.com`,
a workload opening TLS connections to Bedrock, a desktop client reaching a
remote MCP server.

!!! info "Log-based"
    The network connector reads exported logs. It makes no network request
    and captures no packets.

## `network.logs`

Each input record is read as a DNS query, a TLS connection or a flow:

| Source | Records | Notes |
|---|---|---|
| Zeek `dns.log`, `ssl.log`, `conn.log` | DNS queries and answers, TLS server names, connections | TSV with `#fields` headers or JSON (one object per line, `_path` optional) |
| Amazon Route 53 Resolver query logs | DNS queries and answers | JSON or JSONL as delivered to CloudWatch Logs, S3 or Firehose |
| AWS VPC Flow Logs | flows | default version 2 format, or any format with a header line; `REJECT` and `NODATA` rows are skipped |
| Generic JSON or CSV | DNS queries (`query`, `qname`, `domain`…), TLS server names (`sni`, `server_name`), flows (`dst_ip` with `dst_port`) | client address from `client`, `client_ip`, `src_ip`, `srcaddr`… |

The result is one `network-contact` finding per client address and AI
service, with the host names seen, DNS query and TLS connection counts, flow
counts and bytes.

**Host matching is strict.** A host name matches a signature's exact domain
or declared wildcard, never a substring: `www.anthropologie.com`,
`api.gemini.com` (a crypto exchange) and `claude-monet.org` match nothing.
Domain hints weighted below 0.3 are ignored. Only host names that match an AI
signature are kept; other DNS queries are counted as examined records and
never stored.

**Flows are attributed only through the same input.** A flow has addresses,
not names, so it counts towards a service only when:

- its Zeek `uid` and client address link it to a TLS record whose server
  name is an AI host, with matching server address and port when supplied;
- the same client resolved an AI host to that address; or
- no client resolved anything else to that address, and some client resolved
  an AI host to it (weaker evidence, reported as such).

Flow counts and bytes remain separated by connection UID until attribution,
so one AI connection cannot claim another connection's traffic on the same
address and port. UIDs are scoped to the client address. A known non-AI TLS
name blocks DNS and service-port attribution for that connection; conflicting
TLS service identities or endpoints leave its flows unattributed. A missing
UID does not inherit a different connection's TLS name. Without linked TLS
evidence, the DNS rules above still apply.

DNS evidence for a shared address does not attribute flows when it names
multiple services or both AI and non-AI hosts. Ambiguous flows are reported
as a warning that does not make the scan incomplete. A flow to port 11434,
the default Ollama port, is attributed to Ollama only without TLS or DNS
evidence that contradicts it.

**Agent indicators.** Traffic to a coding agent's own service, an MCP server
or a hosted agent runtime (for example `api2.cursor.sh`, `mcp.linear.app` or
`bedrock-agent-runtime`) is tagged `agent-service`. Runs of three or more
connections to a model API at most 30 seconds apart are tagged `agent-loop`.
That cadence is a heuristic: a batch script has the same shape, and a client
that reuses one connection for many requests shows none. Consumer AI sites
such as `chatgpt.com` are AI use, not agent indicators.

Options:

- `input` (required): a log file or a directory of logs. DNS logs and flow
  logs that should be attributed to each other must be in the same input.
- `format`: `zeek`, `route53`, `vpc-flow` or `generic` forces the record
  format; the default `auto` detects it per record.
- `label`: the network or sensor name used in resource ids and as the finding
  account (default `network`).
- `max_records`: the number of records read (default 10,000,000). Reaching
  it makes the scan incomplete.

Malformed lines, records the connector cannot read as DNS, TLS or flow
records, and DNS or TLS records without a client address make the scan
incomplete. Analysis keeps at most 50,000 client addresses, 500,000 flow
groups (client, server address, port and UID), and 500,000 TLS identities
(client and UID). Records beyond any bound are reported and make the scan
incomplete. If TLS identity storage fills, flows with an unretained UID are
left unattributed because a discarded TLS record could contradict DNS.

Client addresses identify a device or a NAT gateway, not a person. Join
findings to DHCP, VPN or asset records before assigning an owner.

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
