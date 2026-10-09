#!/usr/bin/env python3
"""Score scanner outputs against the estate ground truth.

Detection unit = planted artifact (file path). A tool 'hits' an artifact when its
output references that path (or, for aggregate findings, lists it as evidence).
Negatives count as false positives when a tool reports an AI-agent / AI-component
finding anchored on that file (or on the negative repo when the tool reports per repo).
"""
import json, os, re, sys, glob, pathlib
S = pathlib.Path("BENCH_ROOT")
E = S / "estate"; R = S / "results"
TRUTH = json.load(open(E / "truth.json"))
POS = TRUTH["positives"]; NEG = TRUTH["negatives"]; AMB = TRUTH["ambiguous"]

def rel(path: str) -> str:
    """Normalise any absolute/relative path from a tool output to an estate-relative path."""
    p = str(path)
    p = p.replace(str(E) + "/", "")
    p = re.sub(r":\d+$", "", p)
    while p.startswith("./"):
        p = p[2:]
    return p

def hits_from_paths(paths):
    paths = {rel(p) for p in paths if p}
    out = {}
    for a in POS + NEG + AMB:
        ap = a["path"]
        home_rel = ap.split("workstation/home/", 1)[1] if ap.startswith("workstation/home/") else None
        ap_dir = os.path.dirname(ap); home_dir = os.path.dirname(home_rel) if home_rel else None
        def match(p):
            if p == ap or p.endswith("/" + ap):
                return True
            if home_rel and (p == home_rel or p.endswith("/" + home_rel)):
                return True
            # a directory report counts for the single file directly inside it (e.g. a skill folder for its SKILL.md)
            if ap_dir.count("/") >= 2 and (p == ap_dir or p.endswith("/" + ap_dir)):
                return True
            if home_dir and home_dir.count("/") >= 1 and (p == home_dir or p.endswith("/" + home_dir)):
                return True
            return False
        out[a["id"]] = any(match(p) for p in paths)
    return out

# ---------- adapters: each returns dict artifact_id -> bool and a note ----------
def shadowscan():
    paths = []
    for f in list(glob.glob(str(R / "shadowscan" / "repo-*.json"))) + [str(R / "shadowscan" / "workstation.json")]:
        d = json.load(open(f))
        base = "workstation/home" if f.endswith("workstation.json") else "repos/" + os.path.basename(f)[5:-5]
        for x in d.get("findings", []):
            for e in x.get("evidence", []) or []:
                loc = e.get("location")
                if loc:
                    paths.append(base + "/" + rel(loc))
    return hits_from_paths(paths), ""

ADAPTERS = {"shadowscan": shadowscan}

PATHKEY = re.compile(r"(path|file|location|config|source|skill|manifest|target|uri|dir)", re.I)
def harvest(obj, out=None, key=""):
    """Recursively collect string values that look like file paths from a JSON-like object."""
    if out is None: out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            harvest(v, out, str(k))
    elif isinstance(obj, list):
        for v in obj:
            harvest(v, out, key)
    elif isinstance(obj, str):
        if ("estate/" in obj) or (PATHKEY.search(key) and ("/" in obj or obj.endswith((".json", ".py", ".ts", ".md", ".tf", ".yml", ".yaml", ".txt", ".toml", ".go", ".mod", ".xml", ".java", ".js")))):
            for piece in re.split(r"[\s,;'\"()]+", obj):
                if "/" in piece or "." in piece:
                    out.append(piece)
    return out

def load_json(path):
    try:
        return json.load(open(path))
    except Exception:
        try:
            txt = open(path).read()
            start = txt.find("{"); start2 = txt.find("[")
            cands = [i for i in (start, start2) if i >= 0]
            return json.loads(txt[min(cands):]) if cands else None
        except Exception:
            return None

def with_base(paths, base):
    out = []
    for p in paths:
        q = rel(p)
        if q.startswith(("repos/", "workstation/")):
            out.append(q)
        elif base:
            out.append(base + "/" + q)
        else:
            out.append(q)
    return out

def generic(globs_with_base):
    """globs_with_base: list of (glob pattern, base or callable(file)->base)."""
    paths = []
    for pattern, base in globs_with_base:
        for f in glob.glob(str(R / pattern)):
            d = load_json(f)
            if d is None: continue
            b = base(f) if callable(base) else base
            paths += with_base(harvest(d), b)
    return hits_from_paths(paths), ""

def harvest_text(path):
    try:
        txt = open(path, errors="ignore").read()
    except Exception:
        return []
    txt = re.sub(r"\n\s*", "", txt)  # tool wraps long paths across lines
    return re.findall(r"(?:/[\w.@+-]+)+", txt)

AGENTBOM_CLIENT_MAP = {"claude-desktop": "workstation/home/.config/Claude/claude_desktop_config.json", "cursor": "workstation/home/.cursor/mcp.json",
    "vscode-copilot": "workstation/home/.config/Code/User/mcp.json", "claude-code": "workstation/home/.claude.json", "gemini-cli": "workstation/home/.gemini/settings.json",
    "windsurf": "workstation/home/.codeium/windsurf/mcp_config.json"}
def agentbom():
    hits, _ = generic([("agentbom/repo-*.json", repo_base), ("agentbom/cwd-*.json", repo_base), ("agentbom/workstation.json", "workstation/home"), ("agentbom/skills-home.json", "workstation/home"), ("agentbom/skills-repo.json", "repos/agent-skill-pack"), ("agentbom/iac-terraform.json", "repos/infra-terraform")])
    d = load_json(str(R / "agentbom" / "workstation.json")) or {}
    paths = []
    for a in d.get("agents", []):
        if a.get("name") in AGENTBOM_CLIENT_MAP: paths.append(AGENTBOM_CLIENT_MAP[a["name"]])
        for m in a.get("mcp_servers", []) or []:
            if m.get("name") == "notes": paths.append("workstation/home/mcp-servers/poisoned_server.py")
            if m.get("name") == "jira": paths.append("workstation/home/projects/acme-app/.mcp.json")
    # project-directory scans: server names prove the project config was parsed (paths are redacted in output)
    CFG = {"cwd-svc-research-agent.json": ({"filesystem", "zendesk"}, "repos/svc-research-agent/.mcp.json"),
           "cwd-crew-sales-bot.json": ({"hubspot", "serper"}, "repos/crew-sales-bot/.cursor/mcp.json"),
           "cwd-web-assistant-ts.json": ({"inventory", "postgres"}, "repos/web-assistant-ts/.vscode/mcp.json"),
           "cwd-acme-app.json": ({"jira"}, "workstation/home/projects/acme-app/.mcp.json")}
    for fname, (names, art) in CFG.items():
        d2 = load_json(str(R / "agentbom" / fname)) or {}
        found = {m.get("name") for a in d2.get("agents", []) for m in (a.get("mcp_servers") or [])}
        if names & found: paths.append(art)
    # Terraform entities are emitted without file paths: tf:.../aws-bedrock -> bedrock_agent.tf, tf:.../azure-openai -> azure_ai.tf
    d3 = load_json(str(R / "agentbom" / "cwd-infra-terraform.json")) or {}
    names3 = {a.get("name") for a in d3.get("agents", [])}
    if any("aws-bedrock" in str(n) for n in names3): paths.append("repos/infra-terraform/bedrock_agent.tf")
    if any("azure-openai" in str(n) for n in names3): paths.append("repos/infra-terraform/azure_ai.tf")
    # framework entities and package inventories are emitted without file paths; credit the source file they can only come from
    ENT = {"cwd-svc-research-agent.json": [("langchain:react-agent", "repos/svc-research-agent/app/agent.py")],
           "cwd-autogen-team.json": [("pydantic-ai", "repos/autogen-team/team/summarizer.py")]}
    PKG = {"cwd-svc-research-agent.json": ("langgraph", "repos/svc-research-agent/requirements.txt"),
           "cwd-go-mcp-server.json": ("mcp-go", "repos/go-mcp-server/go.mod"),
           "cwd-java-spring-agent.json": ("spring-ai", "repos/java-spring-agent/pom.xml"),
           "cwd-autogen-team.json": ("autogen", "repos/autogen-team/requirements.txt")}
    for fname, pairs in ENT.items():
        d4 = load_json(str(R / "agentbom" / fname)) or {}
        names4 = {str(m.get("name")) for a in d4.get("agents", []) for m in (a.get("mcp_servers") or [])}
        for token, art in pairs:
            if any(token in n for n in names4): paths.append(art)
    for fname, (token, art) in PKG.items():
        d5 = load_json(str(R / "agentbom" / fname)) or {}
        if any(token in str(pk.get("name")) for pk in d5.get("packages", [])): paths.append(art)
    for k, v in hits_from_paths(paths).items():
        hits[k] = hits.get(k) or v
    return hits, ""

def repo_base(f):
    n = os.path.basename(f)
    n = re.sub(r"\.json$", "", n)
    n = re.sub(r"^(repo-|config-)", "", n)
    for cand in sorted(os.listdir(E / "repos")):
        if cand in n:
            return "repos/" + cand
    return "workstation/home" if "workstation" in n or "home" in n or "known" in n or "scan" in n or "discover" in n else ""

def snyk():       return generic([("snyk/inspect*.json", "workstation/home"), ("snyk/scan*.json", "workstation/home")])
def mcpscanner(): return generic([("mcpscanner/known.json", "workstation/home"), ("mcpscanner/known.stdout", "workstation/home"), ("mcpscanner/config-*.json", repo_base), ("mcpscanner/config-*.stdout", repo_base), ("mcpscanner/remote*.json", "workstation/home"), ("mcpscanner/remote.stdout", "workstation/home"), ("mcpscanner/behavioral*", "workstation/home"), ("mcpscanner/stdio-*", "workstation/home")])
def mcpaudit():
    hits, _ = generic([("mcpaudit/scan*.json", "workstation/home"), ("mcpaudit/config-*.json", repo_base), ("mcpaudit/agent-files-*.json", "workstation/home"), ("mcpaudit/shadow.json", "workstation/home")])
    paths = []
    for f in glob.glob(str(R / "mcpaudit" / "*.txt")):
        paths += with_base(harvest_text(f), "workstation/home")
    # agent-files discover prints truncated paths in a table; it reported 2 user-level claude-code skills (217 and 425 chars)
    txt = open(R / "mcpaudit" / "agent-files-discover.txt", errors="ignore").read() if (R / "mcpaudit" / "agent-files-discover.txt").exists() else ""
    if "claude-code-skills" in txt and "Found 2 agent file(s)" in txt:
        paths += ["workstation/home/.claude/skills/helpful-formatter/SKILL.md", "workstation/home/.claude/skills/repo-sync/SKILL.md"]
    for k, v in hits_from_paths(paths).items():
        hits[k] = hits.get(k) or v
    return hits, ""
def skillscanner(): return generic([("skillscanner/repo-*.json", repo_base), ("skillscanner/home.json", "workstation/home")])
def radar():
    """Agentic Radar reports a workflow graph without file paths: credit the agent-framework /
    low-code artifacts of a repository when the exported graph for that repository has agents."""
    hits = {a["id"]: False for a in POS + NEG + AMB}
    for f in glob.glob(str(R / "radar" / "*.json")):
        d = load_json(f)
        if not isinstance(d, dict): continue
        if not d.get("agents") and not any(n.get("node_type") == "agent" for n in d.get("nodes", []) if isinstance(n, dict)): continue
        base = repo_base(f)
        for a in POS + AMB:
            if a["path"].startswith(base + "/") and a.get("category") in ("agent-framework", "lowcode-workflow"):
                hits[a["id"]] = True
    # the autogen export names only the AutoGen agents (run_team.py); PydanticAI (summarizer.py) is not a supported framework
    hits["A24"] = False
    return hits, ""
def radar_unused():
    paths = []
    for f in glob.glob(str(R / "radar" / "*.json")):
        d = load_json(f)
        if d is None: continue
        paths += with_base(harvest(d), repo_base(f))
    for f in glob.glob(str(R / "radar" / "*.html")):
        txt = open(f, errors="ignore").read()
        base = repo_base(f)
        for a in POS + NEG + AMB:
            relp = a["path"].split("/", 2)[-1] if a["path"].startswith("repos/") else None
            if relp and base and a["path"].startswith(base + "/") and (relp in txt or os.path.basename(relp) in txt):
                paths.append(a["path"])
    return hits_from_paths(paths), ""

ADAPTERS.update({"snyk": snyk, "mcpscanner": mcpscanner, "mcpaudit": mcpaudit, "agentbom": agentbom, "skillscanner": skillscanner, "radar": radar})

def main(selected=None):
    rows = []
    for name, fn in ADAPTERS.items():
        if selected and name not in selected: continue
        hits, note = fn()
        tp = [a["id"] for a in POS if hits.get(a["id"])]
        fn_ = [a["id"] for a in POS if not hits.get(a["id"])]
        fp = [a["id"] for a in NEG if hits.get(a["id"])]
        amb = [a["id"] for a in AMB if hits.get(a["id"])]
        rows.append((name, len(tp), len(POS), len(fp), len(NEG), amb, fn_, note, tp, fp))
    for r in rows:
        print(f"{r[0]:14} recall {r[1]}/{r[2]}  FP {r[3]}/{r[4]} {r[9]}  ambiguous-hit {r[5]}  hits {r[8]}")
    json.dump({r[0]: {"tp": r[8], "fp": r[9], "amb": r[5], "missed": r[6]} for r in rows}, open(S / "results" / "score-found.json", "w"), indent=1)

if __name__ == "__main__":
    main(sys.argv[1:] or None)
