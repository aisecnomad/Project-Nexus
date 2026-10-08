#!/usr/bin/env bash
# Install the third-party repository scanners at the commits and versions the
# real-world benchmark was frozen against, each under TOOL_ROOT.
#
#   bash tools/realbench/install_tools.sh /path/to/tool-root
#
# This downloads and builds third-party code and its dependencies. Review the
# pins first, and run it in a disposable machine or container. It installs
# nothing into this repository's environment. ShadowScan itself runs from this
# checkout with the interpreter passed to run.py (--python).
set -euo pipefail

root="${1:?usage: install_tools.sh TOOL_ROOT}"
mkdir -p "$root/third_party" "$root/venvs" "$root/bin"
root="$(cd "$root" && pwd)"

checkout() {  # owner/repo sha [directory-name]
  local dir="$root/third_party/${3:-${1/\//_}}"
  if [[ ! -d "$dir/.git" ]]; then
    git clone --quiet "https://github.com/$1" "$dir"
  fi
  git -C "$dir" fetch --quiet --depth 1 origin "$2" 2>/dev/null || true
  git -C "$dir" -c advice.detachedHead=false checkout --quiet "$2"
  echo "$dir"
}

venv() {  # name source...
  local name="$1"; shift
  uv venv --quiet --allow-existing -p 3.13 "$root/venvs/$name"
  uv pip install --quiet --python "$root/venvs/$name/bin/python" "$@"
}

aibom=$(checkout cisco-ai-defense/aibom 8d7bec099d5ddcd24dbda13a9777f3cf11e2c325)
venv aibom "$aibom/aibom[agentic,llm-openai]"

agentbom=$(checkout msaad00/agent-bom 129615f810e4153cf054a9514bded451ad6b2120 msaad00_agent-bom-latest)
venv agentbom-latest "$agentbom"

agentdiscover=$(checkout Defend-AI-Tech-Inc/agent-discover-scanner a3756cda779a6a46088a3290c77027b0ea5d83c9)
venv agentdiscover "$agentdiscover"

agentguard=$(checkout ak2dev/agentguard-v1 6d4f75d762a350a2ffc43377acb501d44c9d0c67)
venv agentguard "$agentguard[code]"

# safedep/vet v1.20.0; GOTOOLCHAIN=auto fetches the Go release the module asks for.
vet=$(checkout safedep/vet 568cb0e1c90685dd89f07f91c64e97a49228a47f)
(cd "$vet" && GOTOOLCHAIN=auto go build \
  -ldflags "-w -X main.commit=568cb0e1c90685dd89f07f91c64e97a49228a47f -X main.version=v1.20.0" \
  -o "$root/bin/vet" .)

npm install --prefix "$root/cdxgen" --no-audit --no-fund --silent --save-exact @cyclonedx/cdxgen@12.8.5

echo "tools installed under $root"
