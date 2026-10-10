#!/usr/bin/env bash
# Install the repository-surface tools at the versions the real-world benchmark was
# frozen against (see results/freeze.json), each in its own directory under TOOL_ROOT.
#
#   bash tools/benchmark/realworld/install_tools.sh /path/to/tool-root
#
# This downloads and installs third-party code and its dependencies (including
# install scripts), so review the pins first and run it in a disposable machine
# or container. It installs nothing into this repository's environment. The first
# three tools are pinned to the same commits as the synthetic benchmark
# (tools/benchmark/install_tools.sh) so that both benchmarks measure one build.
set -euo pipefail

root="${1:?usage: install_tools.sh TOOL_ROOT}"
mkdir -p "$root/third_party" "$root/venvs" "$root/bin"
root="$(cd "$root" && pwd)"
export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

checkout() {  # owner/repo sha -> prints the checkout directory
  local dir="$root/third_party/${1/\//_}"
  if [[ ! -d "$dir/.git" ]]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "https://github.com/$1"
  fi
  git -C "$dir" fetch -q --depth 1 --no-tags origin "$2"
  git -C "$dir" -c advice.detachedHead=false checkout -q --detach "$2"
  echo "$dir"
}

venv() {  # name source...
  local name="$1"; shift
  uv venv -q --allow-existing -p 3.13 "$root/venvs/$name"
  uv pip install -q --python "$root/venvs/$name/bin/python" "$@"
}

# ShadowScan itself: a regular (not editable) install of the checkout this script lives in, so the
# tool under test is exactly the source tree whose hash run.py records.
venv shadowscan "$repo"

aibom=$(checkout cisco-ai-defense/aibom 8d7bec099d5ddcd24dbda13a9777f3cf11e2c325)
venv aibom "$aibom/aibom[agentic,llm-openai]"

agentbom=$(checkout msaad00/agent-bom 26ed7c15841f9abf7dec70c66c49441ccd317d55)
venv agentbom "$agentbom"

agentdiscover=$(checkout Defend-AI-Tech-Inc/agent-discover-scanner a3756cda779a6a46088a3290c77027b0ea5d83c9)
venv agentdiscover "$agentdiscover"

trusera=$(checkout Trusera/ai-bom 012d53d389ca789f1d5b4a10135d42a6d0fa39f7)
venv trusera "$trusera"

agt=$(checkout microsoft/agent-governance-toolkit 431d20b2fe23e019d5cbd2b41774d43eddb74fa0)
venv agt "$agt/agent-governance-python/agent-discovery"

radar=$(checkout splx-ai/agentic-radar 65a7e4bd01e2034c7cb52e9620eeed287688cc53)
venv radar "$radar"

# SafeDep vet needs a newer Go than some images ship; Go downloads the toolchain it asks for.
vet=$(checkout safedep/vet 948d9bafaf8062f1b83aa5046a6c8b4c64d8856d)
(cd "$vet" && GOTOOLCHAIN=auto go build -o "$root/bin/vet" .)

mkdir -p "$root/cdxgen"
npm install --prefix "$root/cdxgen" --no-audit --no-fund --silent @cyclonedx/cdxgen@12.8.5

echo "tools installed under $root"
