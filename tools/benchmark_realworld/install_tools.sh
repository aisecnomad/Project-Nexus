#!/usr/bin/env bash
# Install the real-world benchmark's tools at pinned versions under TOOL_ROOT.
#
#   bash tools/benchmark_realworld/install_tools.sh /opt/rwbench/tools
#
# Packages come from PyPI and the Go module proxy. Two endpoint scripts are
# GitHub-only; the operator places their checkouts under
# TOOL_ROOT/third_party (see tools/benchmark_realworld/README.md).
#
# This downloads and installs third-party code, and installing a package can run
# its build hooks. Run it on a disposable machine or container.
set -euo pipefail

root="${1:?usage: install_tools.sh TOOL_ROOT}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$root/venvs" "$root/bin" "$root/third_party"
root="$(cd "$root" && pwd)"
py="$(command -v python3)"

venv() {  # name requirement...
  local name="$1"
  shift
  uv venv --quiet --allow-existing -p "$py" "$root/venvs/$name"
  if (($#)); then
    uv pip install --quiet --python "$root/venvs/$name/bin/python" "$@"
  fi
}

venv aibom 'cisco-aibom[agentic,llm-openai]==1.10.0'
venv agentbom agent-bom==0.108.2
venv agentdiscover agentdiscover==2.9.5
venv snyk snyk-agent-scan==0.6.8
venv mcpscanner cisco-ai-mcp-scanner==4.8.6
venv mcpaudit mcp-audit-scanner==0.18.2
venv shadowmcp shadow-mcp==0.2.0

# ShadowScan runs from this checkout (PYTHONPATH); only its locked runtime
# dependencies are installed here, hash-checked.
venv shadowscan
uv pip install --quiet --require-hashes --python "$root/venvs/shadowscan/bin/python" -r "$here/requirements.lock"

GOBIN="$root/bin" go install github.com/safedep/vet@v1.17.5

echo "tools installed under $root"
