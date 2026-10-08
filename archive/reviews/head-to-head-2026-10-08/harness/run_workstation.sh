#!/bin/bash
S=$BENCH
H=$S/estate/workstation/home
R=$S/results
T=$R/timing-workstation.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
export PATH=$PATH:/usr/local/bin
# Snyk Agent Scan: discover well-known configs under HOME, run servers for inspection
t snyk-scan env HOME=$H $S/venvs/snyk/bin/snyk-agent-scan scan --json --show-full-discovery --dangerously-run-mcp-servers --server-timeout 60 --storage-file $R/snyk/storage.json --print-errors > $R/snyk/scan.json 2> $R/snyk/scan.stderr
t snyk-inspect env HOME=$H $S/venvs/snyk/bin/snyk-agent-scan inspect --json --storage-file $R/snyk/storage2.json > $R/snyk/inspect.json 2> $R/snyk/inspect.stderr
# Cisco MCP Scanner: known client configs (YARA only, no API keys)
t mcpscanner-known env HOME=$H $S/venvs/mcpscanner/bin/mcp-scanner --analyzers yara_analyzer --format raw --output $R/mcpscanner/known.json --stdio-timeout 60 known-configs > $R/mcpscanner/known.stdout 2> $R/mcpscanner/known.stderr
for c in repos/svc-research-agent/.mcp.json repos/crew-sales-bot/.cursor/mcp.json repos/web-assistant-ts/.vscode/mcp.json workstation/home/projects/acme-app/.mcp.json workstation/home/.claude.json workstation/home/.gemini/settings.json workstation/home/.config/Code/User/mcp.json; do
  n=$(echo $c | tr '/' '_'); t "mcpscanner-config-$n" env HOME=$H $S/venvs/mcpscanner/bin/mcp-scanner --analyzers yara_analyzer --format raw --output $R/mcpscanner/config-$n.json --stdio-timeout 60 config --config-path $S/estate/$c > $R/mcpscanner/config-$n.stdout 2> $R/mcpscanner/config-$n.stderr
done
# mcp-audit
t mcpaudit-discover env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit discover > $R/mcpaudit/discover.txt 2> $R/mcpaudit/discover.stderr
t mcpaudit-scan env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit scan --json -o $R/mcpaudit/scan.json > $R/mcpaudit/scan.stdout 2> $R/mcpaudit/scan.stderr
t mcpaudit-agentfiles env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit agent-files > $R/mcpaudit/agent-files.txt 2> $R/mcpaudit/agent-files.stderr
t mcpaudit-shadow env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit shadow > $R/mcpaudit/shadow.txt 2> $R/mcpaudit/shadow.stderr
for c in repos/svc-research-agent/.mcp.json repos/crew-sales-bot/.cursor/mcp.json repos/web-assistant-ts/.vscode/mcp.json workstation/home/projects/acme-app/.mcp.json; do
  n=$(echo $c | tr '/' '_'); t "mcpaudit-config-$n" env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit scan -p $S/estate/$c --json -o $R/mcpaudit/config-$n.json > $R/mcpaudit/config-$n.stdout 2> $R/mcpaudit/config-$n.stderr
done
# agent-bom workstation discovery
t agentbom-where env HOME=$H $S/venvs/agentbom/bin/agent-bom where > $R/agentbom/where.txt 2> $R/agentbom/where.stderr
t agentbom-workstation env HOME=$H $S/venvs/agentbom/bin/agent-bom scan --offline -f json -o $R/agentbom/workstation.json > $R/agentbom/workstation.stdout 2> $R/agentbom/workstation.stderr
t agentbom-skills-home env HOME=$H $S/venvs/agentbom/bin/agent-bom skills scan $H -f json -o $R/agentbom/skills-home.json > $R/agentbom/skills-home.stdout 2> $R/agentbom/skills-home.stderr
# Cisco Skill Scanner on user skills
t skillscanner-home $S/venvs/skillscanner/bin/skill-scanner scan-all $H/.claude/skills --recursive --use-behavioral --format json --output $R/skillscanner/home.json > $R/skillscanner/home.stdout 2> $R/skillscanner/home.stderr
echo DONE >> $T
