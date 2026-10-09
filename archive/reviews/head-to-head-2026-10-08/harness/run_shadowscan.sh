#!/bin/bash
S=$BENCH
SS=$S/venvs/shadowscan/bin/shadowscan
R=$S/results/shadowscan
: > $R/timing.tsv
for repo in $S/estate/repos/*/; do
  name=$(basename $repo)
  start=$(date +%s.%N)
  $SS code "$repo" --format json -o $R/repo-$name.json > $R/repo-$name.stdout 2> $R/repo-$name.stderr
  code=$?
  end=$(date +%s.%N)
  printf "%s\t%s\t%.2f\n" "repo-$name" "$code" "$(echo "$end - $start" | bc)" >> $R/timing.tsv
done
start=$(date +%s.%N)
$SS code $S/estate/workstation/home --format json -o $R/workstation.json > $R/workstation.stdout 2> $R/workstation.stderr
printf "%s\t%s\t%.2f\n" "workstation" "$?" "$(echo "$(date +%s.%N) - $start" | bc)" >> $R/timing.tsv
cd /home/user/Project-Nexus
start=$(date +%s.%N)
$SS scan -c examples/shadowscan.offline.yaml --format json -o $R/offline-demo.json > $R/offline-demo.stdout 2> $R/offline-demo.stderr
printf "%s\t%s\t%.2f\n" "offline-demo" "$?" "$(echo "$(date +%s.%N) - $start" | bc)" >> $R/timing.tsv
echo DONE >> $R/timing.tsv
