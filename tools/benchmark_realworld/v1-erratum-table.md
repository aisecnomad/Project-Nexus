
## v1 repo surface: v1 rule and v2 error rule
| Tool | Scored | Errors on clean cases | Errors on positives | Specificity v1 | Specificity v2 | Recall v1 | Recall v2 | BA v1 | BA v2 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| agent-bom | 39 | 0 | 0 | 0.40 | 0.40 | 1.00 | 1.00 | 0.70 | 0.70 |
| agentdiscover | 39 | 0 | 0 | 0.50 | 0.50 | 0.72 | 0.72 | 0.61 | 0.61 |
| cisco-aibom | 39 | 1 | 4 | 0.70 | 0.60 | 0.86 | 0.86 | 0.78 | 0.73 |
| mcp-audit | 39 | 0 | 0 | 0.90 | 0.90 | 0.48 | 0.48 | 0.69 | 0.69 |
| safedep-vet | 39 | 0 | 0 | 1.00 | 1.00 | 0.31 | 0.31 | 0.66 | 0.66 |
| shadowscan-dedicated | 39 | 2 | 13 | 0.80 | 0.60 | 0.55 | 0.55 | 0.68 | 0.58 |
| shadowscan | 39 | 3 | 13 | 0.90 | 0.60 | 0.55 | 0.55 | 0.73 | 0.58 |

## v1 endpoint surface: v1 rule and v2 error rule
| Tool | Scored | Errors on clean cases | Errors on positives | Specificity v1 | Specificity v2 | Recall v1 | Recall v2 | BA v1 | BA v2 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| agent-bom | 41 | 0 | 0 | 0.82 | 0.82 | 1.00 | 1.00 | 0.91 | 0.91 |
| agentdiscover | 41 | 0 | 0 | 0.35 | 0.35 | 1.00 | 1.00 | 0.68 | 0.68 |
| ai-detector | 41 | 0 | 0 | 0.93 | 0.93 | 0.00 | 0.00 | 0.46 | 0.46 |
| cisco-aibom | 41 | 4 | 1 | 0.25 | 0.15 | 0.00 | 0.00 | 0.12 | 0.07 |
| cisco-mcp-scanner | 41 | 0 | 0 | 1.00 | 1.00 | 0.00 | 0.00 | 0.50 | 0.50 |
| claw-hunter | 41 | 0 | 0 | 1.00 | 1.00 | 0.00 | 0.00 | 0.50 | 0.50 |
| mcp-audit | 41 | 0 | 0 | 1.00 | 1.00 | 0.00 | 0.00 | 0.50 | 0.50 |
| safedep-vet | 41 | 0 | 0 | 0.75 | 0.75 | 1.00 | 1.00 | 0.88 | 0.88 |
| shadow-mcp | 41 | 0 | 0 | 1.00 | 1.00 | 0.00 | 0.00 | 0.50 | 0.50 |
| shadowscan-dedicated | 41 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| shadowscan | 41 | 16 | 1 | 0.55 | 0.15 | 0.00 | 0.00 | 0.28 | 0.07 |
| snyk-agent-scan | 41 | 0 | 0 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
