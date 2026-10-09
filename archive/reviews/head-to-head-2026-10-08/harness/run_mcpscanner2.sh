#!/bin/bash
S=$BENCH
H=$S/estate/workstation/home
R=$S/results
T=$R/timing-mcpscanner.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
export PATH=$PATH:/usr/local/bin MCP_SCANNER_STDIO_TIMEOUT=45
rm -f $R/mcpscanner/*
MS=$S/venvs/mcpscanner/bin/mcp-scanner
t mcpscanner-known env HOME=$H $MS --analyzers yara --format raw --output $R/mcpscanner/known.json known-configs < /dev/null > $R/mcpscanner/known.stdout 2> $R/mcpscanner/known.stderr
for c in repos/svc-research-agent/.mcp.json repos/crew-sales-bot/.cursor/mcp.json repos/web-assistant-ts/.vscode/mcp.json workstation/home/projects/acme-app/.mcp.json workstation/home/.claude.json workstation/home/.gemini/settings.json workstation/home/.config/Code/User/mcp.json; do
  n=$(echo $c | tr '/' '_'); t "mcpscanner-config-$n" env HOME=$H $MS --analyzers yara --format raw --output $R/mcpscanner/config-$n.json config --config-path $S/estate/$c < /dev/null > $R/mcpscanner/config-$n.stdout 2> $R/mcpscanner/config-$n.stderr
done
t mcpscanner-remote env HOME=$H $MS --analyzers yara --format raw --output $R/mcpscanner/remote-8765.json remote --server-url http://127.0.0.1:8765/mcp < /dev/null > $R/mcpscanner/remote.stdout 2> $R/mcpscanner/remote.stderr
t mcpscanner-behavioral env HOME=$H $MS --analyzers behavioral --format raw --output $R/mcpscanner/behavioral.json behavioral $H/mcp-servers < /dev/null > $R/mcpscanner/behavioral.stdout 2> $R/mcpscanner/behavioral.stderr
t mcpscanner-stdio-poisoned env HOME=$H $MS --analyzers yara --format raw --output $R/mcpscanner/stdio-poisoned.json stdio --stdio-command $S/venvs/mcp/bin/python --stdio-arg $H/mcp-servers/poisoned_server.py < /dev/null > $R/mcpscanner/stdio-poisoned.stdout 2> $R/mcpscanner/stdio-poisoned.stderr
echo DONE >> $T
