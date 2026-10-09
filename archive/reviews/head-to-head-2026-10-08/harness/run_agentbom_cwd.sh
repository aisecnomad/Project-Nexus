#!/bin/bash
S=$BENCH
H=$S/estate/workstation/home
R=$S/results
T=$R/timing-agentbom-cwd.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
for repo in $S/estate/repos/*/; do
  name=$(basename $repo)
  ( cd "$repo" && t "agentbom-cwd-$name" env HOME=$H $S/venvs/agentbom/bin/agent-bom scan -p . --offline -f json -o $R/agentbom/cwd-$name.json < /dev/null > $R/agentbom/cwd-$name.stdout 2> $R/agentbom/cwd-$name.stderr )
done
( cd $S/estate/workstation/home/projects/acme-app && t "agentbom-cwd-acme-app" env HOME=$H $S/venvs/agentbom/bin/agent-bom scan -p . --offline -f json -o $R/agentbom/cwd-acme-app.json < /dev/null > $R/agentbom/cwd-acme-app.stdout 2> $R/agentbom/cwd-acme-app.stderr )
echo DONE >> $T
