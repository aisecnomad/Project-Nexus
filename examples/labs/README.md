# Labs

Hands-on, notebook-based exercises for operating ShadowScan. Each lab pins the
scanner to a reviewed commit SHA, installs it into its own virtual environment,
fetches public example repositories at pinned commits without executing their
code, and needs no credential.

| Lab | What it covers | Time |
|---|---|---|
| [`shadow-agent-scan-lab.ipynb`](shadow-agent-scan-lab.ipynb) | Discovering unregistered AI agents in a GitHub and a GitLab repository: one discovery scan, reading a finding from its evidence and risk factors, reconciling against an inventory (empty inventory, generated stub, one exact approval, rescan, `diff`), an HTML report and the `--fail-on` gate. | ~30 min |

Open a lab in JupyterLab, VS Code or Google Colab with a Python 3.11+ kernel on
Linux or macOS (the scanner refuses Windows; use WSL2 or Colab) and run the cells
in order. Reports and inventories the lab writes are sensitive operator data;
keep them private if you adapt a lab to internal repositories.

Labs are validated against the scanner commit named in their first cell. When
you re-pin a lab to a newer revision, rerun it end to end and update the recorded
observations.
