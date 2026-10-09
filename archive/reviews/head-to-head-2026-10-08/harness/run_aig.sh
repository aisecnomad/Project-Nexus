#!/bin/bash
S=$BENCH
R=$S/results
T=$R/timing-aig.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
cd $S/src/aig
t aig-targets env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy $S/bin/ai-infra-guard scan --target http://127.0.0.1:11434 --target http://127.0.0.1:8765 --fps data/fingerprints --vul data/vuln --lang en --timeout 10 -o $R/aig/targets.json > $R/aig/targets.stdout 2> $R/aig/targets.stderr
t aig-localscan env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy $S/bin/ai-infra-guard scan --localscan --fps data/fingerprints --vul data/vuln --lang en --timeout 10 -o $R/aig/localscan.json > $R/aig/localscan.stdout 2> $R/aig/localscan.stderr
echo DONE >> $T
