#!/bin/bash
S=$BENCH
export PIP_CERT=/root/.ccr/ca-bundle.crt PIP_DISABLE_PIP_VERSION_CHECK=1
inst() { name=$1; shift; ( python3 -m venv $S/venvs/$name && $S/venvs/$name/bin/pip install -q --upgrade pip >/dev/null 2>&1; $S/venvs/$name/bin/pip install -q "$@" ) > $S/logs/install-$name.log 2>&1; echo "$name exit=$?" >> $S/logs/install-summary.log; }
: > $S/logs/install-summary.log
inst snyk snyk-agent-scan &
inst aibom cisco-aibom &
inst mcpscanner cisco-ai-mcp-scanner &
inst skillscanner cisco-ai-skill-scanner &
wait
inst agentbom agent-bom &
inst radar agentic-radar &
inst mcpaudit mcp-audit-scanner &
inst shadowscan -r /home/user/Project-Nexus/requirements.lock --require-hashes &
wait
$S/venvs/shadowscan/bin/pip install -q --no-deps --no-build-isolation -e /home/user/Project-Nexus >> $S/logs/install-shadowscan.log 2>&1; echo "shadowscan-editable exit=$?" >> $S/logs/install-summary.log
echo DONE >> $S/logs/install-summary.log
