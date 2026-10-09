#!/usr/bin/env python3
"""Per-tool, per-artifact evidence summary for the typed-classification review."""
import json, glob, os, re, sys, pathlib
S = pathlib.Path("BENCH_ROOT")
R = S / "results"; E = S / "estate"
truth = json.load(open(E / "truth.json"))
arts = truth["positives"] + truth["negatives"] + truth["ambiguous"]
def tail(p): return p.split("/")[-1]

def shadowscan():
    print("##### ShadowScan: finding kind / risk / title -> evidence locations")
    for f in sorted(glob.glob(str(R / "shadowscan" / "repo-*.json"))) + [str(R / "shadowscan" / "workstation.json")]:
        d = json.load(open(f)); print("--", os.path.basename(f))
        for x in d["findings"]:
            locs = sorted({(e.get("location") or "").split(":")[0] for e in x.get("evidence", [])})
            sigs = sorted({e.get("signature") for e in x.get("evidence", []) if e.get("signature")})[:6]
            print(f"   {x['kind']:16} {x['risk']['level']:8} shadow={x.get('shadow')} | {x['title'][:80]} | files={locs[:8]} | sigs={sigs}")

def agentbom():
    print("##### agent-bom (cwd mode): agents / servers / prompts / findings")
    for f in sorted(glob.glob(str(R / "agentbom" / "cwd-*.json"))) + [str(R / "agentbom" / "workstation.json"), str(R / "agentbom" / "iac-terraform.json"), str(R / "agentbom" / "skills-home.json"), str(R / "agentbom" / "skills-repo.json")]:
        try: d = json.load(open(f))
        except Exception as e: print("--", os.path.basename(f), "ERR", e); continue
        print("--", os.path.basename(f), "summary:", (d.get("ai_bom_entities") or {}).get("summary") or d.get("summary"))
        for a in d.get("agents", []):
            md = a.get("metadata") or {}
            print(f"   agent {a.get('name')} [{a.get('agent_type')}] servers={[m.get('name') for m in a.get('mcp_servers', [])][:8]} prompts={sorted({sp.get('file') for sp in md.get('system_prompts', [])})[:4]} meta={ {k: str(v)[:60] for k, v in md.items() if k not in ('system_prompts',)} }")
        for fnd in d.get("findings", [])[:10]:
            print(f"   finding {fnd.get('severity')} {fnd.get('rule_id') or fnd.get('id')} {str(fnd.get('title') or fnd.get('message'))[:70]} @ {tail(str(fnd.get('file_path') or fnd.get('path') or ''))}")
        for fl in d.get("files", [])[:6]:
            print(f"   file {tail(fl.get('path',''))} verdict={fl.get('verdict') or fl.get('status')} findings={[ (x.get('severity'), str(x.get('title') or x.get('rule'))[:50]) for x in fl.get('findings', [])][:4]}")

def mcpaudit():
    print("##### mcp-audit: servers and finding rules")
    for f in [str(R / "mcpaudit" / "scan.json"), str(R / "mcpaudit" / "scan-connect2.json")] + sorted(glob.glob(str(R / "mcpaudit" / "config-*.json"))):
        try: d = json.load(open(f))
        except Exception as e: print("--", os.path.basename(f), "ERR", e); continue
        print("--", os.path.basename(f), "servers:", [(s.get("name"), s.get("client")) for s in d.get("servers", [])])
        agg = {}
        for x in d.get("findings", []):
            agg.setdefault((x.get("severity"), x.get("rule_id"), x.get("title")), set()).add(x.get("server"))
        for k, v in sorted(agg.items(), key=lambda kv: str(kv[0])):
            if k[0] in ("CRITICAL", "HIGH", "MEDIUM"): print(f"   {k[0]:8} {k[1]} {str(k[2])[:60]} -> {sorted(str(s) for s in v)[:6]}")
    for f in sorted(glob.glob(str(R / "mcpaudit" / "agent-files-*.txt"))):
        print("--", os.path.basename(f)); print("   " + open(f, errors="ignore").read().replace("\n", "\n   ")[:900])

def snyk():
    print("##### Snyk Agent Scan")
    for f in sorted(glob.glob(str(R / "snyk" / "inspect*.json"))):
        try: d = json.load(open(f))
        except Exception as e: print("--", os.path.basename(f), "ERR", e); continue
        print("--", os.path.basename(f))
        for k, v in d.items():
            if isinstance(v, dict) and "servers" in v:
                print(f"   client={v.get('client')} path=...{v.get('path','')[-40:]} servers={[s.get('name') for s in v.get('servers', [])]} skills={[tail(str(s.get('path') or s.get('name'))) for s in v.get('skills', [])]}")
    for f in [str(R / "snyk" / "scan2.json"), str(R / "snyk" / "scan3.json")]:
        if not os.path.exists(f) or os.path.getsize(f) == 0: continue
        try: d = json.load(open(f))
        except Exception as e: print("--", os.path.basename(f), "ERR", e); continue
        print("--", os.path.basename(f), "top keys:", list(d.keys())[:8] if isinstance(d, dict) else type(d))
        txt = json.dumps(d)
        for m in re.finditer(r'"(issues|findings|labels|risks)":\s*\[(?!\])', txt): print("   ctx:", txt[m.start():m.start()+300])
        break

def mcpscanner():
    print("##### Cisco MCP Scanner (yara / behavioral)")
    for f in sorted(glob.glob(str(R / "mcpscanner" / "*.stdout"))):
        txt = open(f).read(); i = txt.find("{")
        if i < 0: print("--", os.path.basename(f), "no json:", txt[:120].replace("\n", " ")); continue
        try: d = json.loads(txt[i:])
        except Exception as e: print("--", os.path.basename(f), "json err", e); continue
        res = d.get("scan_results") or d.get("results") or []
        print("--", os.path.basename(f), "source:", d.get("server_url") or d.get("config_path") or d.get("source"), "results:", len(res))
        for r in res[:12]:
            fa = r.get("findings") or {}
            flagged = {k: v.get("severity") for k, v in fa.items() if isinstance(v, dict) and v.get("severity") not in (None, "SAFE")}
            print(f"   tool={r.get('tool_name')} server={str(r.get('server_source') or r.get('server_url') or '')[:40]} status={r.get('status')} safe={r.get('is_safe')} flagged={flagged} threats={[v.get('threat_names') for v in fa.values() if isinstance(v, dict) and v.get('threat_names')][:2]}")

def skillscanner():
    print("##### Cisco Skill Scanner")
    for f in sorted(glob.glob(str(R / "skillscanner" / "*.json"))):
        try: d = json.load(open(f))
        except Exception as e: print("--", os.path.basename(f), "ERR", e); continue
        print("--", os.path.basename(f), "scanned:", d.get("summary", {}).get("total_skills_scanned"))
        for r in d.get("results", []):
            print(f"   skill={r.get('skill_name')} safe={r.get('is_safe')} max={r.get('max_severity')} n={r.get('findings_count')} rules={[x.get('rule_id') for x in r.get('findings', []) if x.get('severity') in ('CRITICAL','HIGH')][:6]}")

def radar():
    print("##### Agentic Radar (graph exports)")
    for f in sorted(glob.glob(str(R / "radar" / "*.json"))):
        try: d = json.load(open(f))
        except Exception: continue
        print(f"-- {os.path.basename(f)} agents={[a.get('name') for a in d.get('agents', [])]} agent_nodes={[n.get('name') for n in d.get('nodes', []) if n.get('node_type') == 'agent']} tools={[t.get('name') for t in d.get('tools', [])][:6]}")
    import collections
    outcomes = collections.Counter()
    for f in sorted(glob.glob(str(R / "radar" / "*.stdout"))):
        txt = open(f, errors="ignore").read()
        key = "found" if "didn't find" not in txt and "Error" not in txt and os.path.getsize(f) > 0 else ("none" if "didn't find" in txt else "error")
        outcomes[key] += 1
    print("   stdout outcomes:", dict(outcomes))

def aig():
    print("##### AI-Infra-Guard")
    for f in ("targets.stdout", "localscan.stdout"):
        txt = open(R / "aig" / f, errors="ignore").read()
        lines = [l for l in txt.splitlines() if l.startswith("http://") or "CVE-" in l[:60] or "[HIGH]" in l or "[MEDIUM]" in l or "[CRITICAL]" in l]
        print("--", f); [print("   ", re.sub(r"\x1b\[[0-9;]*m", "", l)[:120]) for l in lines[:12]]

for name in (sys.argv[1:] or ["shadowscan", "agentbom", "mcpaudit", "snyk", "mcpscanner", "skillscanner", "radar", "aig"]):
    globals()[name]()
