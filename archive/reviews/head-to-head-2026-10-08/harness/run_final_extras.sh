#!/bin/bash
S=$BENCH
H=$S/estate/workstation/home
R=$S/results
T=$R/timing-final-extras.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
export PATH=$PATH:/usr/local/bin MCP_SCANNER_STDIO_TIMEOUT=45
MS=$S/venvs/mcpscanner/bin/mcp-scanner
for c in workstation/home/.config/Claude/claude_desktop_config.json workstation/home/.codeium/windsurf/mcp_config.json; do
  n=$(echo $c | tr '/' '_'); t "mcpscanner-config-$n" env HOME=$H $MS --analyzers yara --format raw config --config-path $S/estate/$c < /dev/null > $R/mcpscanner/config-$n.stdout 2> $R/mcpscanner/config-$n.stderr
done
cd /home/user/Project-Nexus
t snyk-scan-analysis env HOME=$H COLUMNS=100000 TERM=dumb $S/venvs/snyk/bin/snyk-agent-scan scan --json --show-analysis-results --dangerously-run-mcp-servers --server-timeout 30 --storage-file $R/snyk/storage5.json --print-errors < /dev/null > $R/snyk/scan3.json 2> $R/snyk/scan3.stderr
echo DONE >> $T
