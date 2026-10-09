#!/bin/bash
S=$BENCH
R=$S/results
T=$R/timing-repos.tsv; : > $T
t() { local label=$1; shift; local start=$(date +%s.%N); "$@"; local code=$?; printf "%s\t%s\t%.2f\n" "$label" "$code" "$(echo "$(date +%s.%N) - $start" | bc)" >> $T; }
for repo in $S/estate/repos/*/; do
  name=$(basename $repo)
  # cisco-aibom skipped: requires --llm-model (LLM credentials) and has no offline mode
  t "agentbom-$name" $S/venvs/agentbom/bin/agent-bom scan -p "$repo" --no-discover --offline -f json -o $R/agentbom/repo-$name.json > $R/agentbom/repo-$name.stdout 2> $R/agentbom/repo-$name.stderr
  t "skillscanner-$name" $S/venvs/skillscanner/bin/skill-scanner scan-all "$repo" --recursive --use-behavioral --format json --output $R/skillscanner/repo-$name.json > $R/skillscanner/repo-$name.stdout 2> $R/skillscanner/repo-$name.stderr
  for fw in langgraph crewai n8n openai-agents autogen; do
    t "radar-$name-$fw" $S/venvs/radar/bin/agentic-radar scan $fw -i "$repo" -o $R/radar/$name-$fw.html > $R/radar/$name-$fw.stdout 2> $R/radar/$name-$fw.stderr
    t "radarjson-$name-$fw" $S/venvs/radar/bin/agentic-radar scan $fw -i "$repo" --export-graph-json -o $R/radar/$name-$fw.json > $R/radar/$name-$fw.json.stdout 2> $R/radar/$name-$fw.json.stderr
  done
done
t agentbom-iac $S/venvs/agentbom/bin/agent-bom iac $S/estate/repos/infra-terraform -f json -o $R/agentbom/iac-terraform.json > $R/agentbom/iac.stdout 2> $R/agentbom/iac.stderr
t agentbom-skills-repo $S/venvs/agentbom/bin/agent-bom skills scan $S/estate/repos/agent-skill-pack -f json -o $R/agentbom/skills-repo.json > $R/agentbom/skills-repo.stdout 2> $R/agentbom/skills-repo.stderr
# cisco-aibom all-repos skipped (requires LLM)
echo DONE >> $T
