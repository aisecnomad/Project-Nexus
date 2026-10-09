#!/bin/bash
S=$BENCH
H=$S/estate/workstation/home
R=$S/results
T=$R/timing-mcpaudit-extra.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
export PATH=$PATH:/usr/local/bin
t mcpaudit-scan-connect env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit scan --connect --json -o $R/mcpaudit/scan-connect.json < /dev/null > $R/mcpaudit/scan-connect.stdout 2> $R/mcpaudit/scan-connect.stderr
t mcpaudit-shadow-json env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit shadow --json < /dev/null > $R/mcpaudit/shadow.json 2> $R/mcpaudit/shadow-json.stderr
for sub in scan discover list; do
  t mcpaudit-agentfiles-$sub env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit agent-files $sub < /dev/null > $R/mcpaudit/agent-files-$sub.txt 2> $R/mcpaudit/agent-files-$sub.stderr
  t mcpaudit-agentfiles-$sub-json env HOME=$H $S/venvs/mcpaudit/bin/mcp-audit agent-files $sub --json < /dev/null > $R/mcpaudit/agent-files-$sub.json 2> $R/mcpaudit/agent-files-$sub-json.stderr
done
echo DONE >> $T
