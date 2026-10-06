#!/usr/bin/env bash
# Install the ten third-party tools at the commits the benchmark was
# pre-registered against, each in its own directory under TOOL_ROOT.
#
#   bash tools/benchmark/install_tools.sh /path/to/tool-root
#
# This downloads and installs third-party code and its dependencies. Review
# the pinned commits first, and run it in a disposable machine or container.
# It installs nothing into this repository's environment.
set -euo pipefail

root="${1:?usage: install_tools.sh TOOL_ROOT}"
mkdir -p "$root/third_party" "$root/venvs" "$root/bin"
root="$(cd "$root" && pwd)"

checkout() {  # owner/repo sha
  local dir="$root/third_party/${1/\//_}"
  if [[ ! -d "$dir/.git" ]]; then
    git clone --quiet "https://github.com/$1" "$dir"
  fi
  git -C "$dir" fetch --quiet --depth 1 origin "$2" 2>/dev/null || true
  git -C "$dir" -c advice.detachedHead=false checkout --quiet "$2"
  echo "$dir"
}

venv() {  # name source...
  local name="$1"; shift
  uv venv --quiet --allow-existing -p 3.13 "$root/venvs/$name"
  uv pip install --quiet --python "$root/venvs/$name/bin/python" "$@"
}

aibom=$(checkout cisco-ai-defense/aibom 8d7bec099d5ddcd24dbda13a9777f3cf11e2c325)
venv aibom "$aibom/aibom[agentic,llm-openai]"

agentbom=$(checkout msaad00/agent-bom 26ed7c15841f9abf7dec70c66c49441ccd317d55)
venv agentbom "$agentbom"

agentdiscover=$(checkout Defend-AI-Tech-Inc/agent-discover-scanner a3756cda779a6a46088a3290c77027b0ea5d83c9)
venv agentdiscover "$agentdiscover"

snyk=$(checkout snyk/agent-scan 69ce32c6e5ae67e5d688efee9e9c45f7de7046c4)
venv snyk "$snyk"

mcpscanner=$(checkout cisco-ai-defense/mcp-scanner f817899d9391b099f395acd5ae7ff435dccf2a47)
venv mcpscanner "$mcpscanner"

osai=$(checkout alebgl77/open-shadow-ai 715044e079c48ec522ef50cb3ee9f927c4666e6d)
venv openshadowai "$osai"

sonar=$(checkout knostic/AgentSonar 8658b67741eb002e8937e3f7c8f3afac9daab148)
# Linux builds need libpcap headers (libpcap-dev / libpcap-devel).
(cd "$sonar" && CGO_ENABLED=1 go build -o "$root/bin/agentsonar" ./cmd/agentsonar)

detector=$(checkout mizcausevic-dev/shadow-ai-detector f2bd5ab95018ec96eca47b0eafa20c5fb014f2d7)
(cd "$detector" && npm ci --no-audit --no-fund --silent && npm run --silent build)

checkout backslash-security/claw-hunter 4125c4fc9892140d031d00da7c0114a7863fdfcf >/dev/null
checkout shamo0/AI-Detector fa673ef9a990a2f54538bc1921a8e82f2a404ea5 >/dev/null

echo "tools installed under $root"
