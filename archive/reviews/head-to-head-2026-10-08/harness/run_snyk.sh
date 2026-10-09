#!/bin/bash
S=$BENCH
H=$S/estate/workstation/home
R=$S/results
T=$R/timing-snyk.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
export PATH=$PATH:/usr/local/bin
cd /home/user/Project-Nexus
if [ ! -s $R/snyk/scan2.json ]; then
  t snyk-scan-run env HOME=$H $S/venvs/snyk/bin/snyk-agent-scan scan --json --show-full-discovery --dangerously-run-mcp-servers --server-timeout 45 --storage-file $R/snyk/storage4.json --print-errors --verbose < /dev/null > $R/snyk/scan2.json 2> $R/snyk/scan2.stderr
fi
for p in repos/svc-research-agent repos/crew-sales-bot repos/web-assistant-ts workstation/home/projects/acme-app repos/agent-skill-pack; do
  n=$(echo $p | tr '/' '_')
  ( cd $S/estate/$p && t "snyk-inspect-cwd-$n" env HOME=$H $S/venvs/snyk/bin/snyk-agent-scan inspect --json --storage-file $R/snyk/storage-$n.json < /dev/null > $R/snyk/inspect-cwd-$n.json 2> $R/snyk/inspect-cwd-$n.stderr )
done
for c in repos/svc-research-agent/.mcp.json repos/crew-sales-bot/.cursor/mcp.json repos/web-assistant-ts/.vscode/mcp.json workstation/home/projects/acme-app/.mcp.json; do
  n=$(echo $c | tr '/' '_')
  t "snyk-inspect-file-$n" env HOME=$H $S/venvs/snyk/bin/snyk-agent-scan inspect --json --storage-file $R/snyk/storage-x-$n.json $S/estate/$c < /dev/null > $R/snyk/inspect-file-$n.json 2> $R/snyk/inspect-file-$n.stderr
done
echo DONE >> $T
