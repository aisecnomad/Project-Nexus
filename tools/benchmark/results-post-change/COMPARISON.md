| Variant | Surface | Recall | Specificity | F1 | Agent recall | LLM-only called agentic | Negatives called agentic | Errors |
|---|---|---|---|---|---|---|---|---|
| before (published) | repo | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.95 (0.90–0.97) | 0/45 | 0/120 | 0 |
| before (published) | endpoint | 0.70 (0.63–0.76) | 1.00 (0.97–1.00) | 0.82 | 0.93 (0.88–0.96) | 0/45 | 0/120 | 0 |
| before (published) | network | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.00 (0.00–0.03) | 0/45 | 0/120 | 0 |
| before, agent rule re-scored | repo | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 1.00 (0.97–1.00) | 0/45 | 0/120 | 0 |
| before, agent rule re-scored | endpoint | 0.70 (0.63–0.76) | 1.00 (0.97–1.00) | 0.82 | 0.93 (0.88–0.96) | 0/45 | 0/120 | 0 |
| before, agent rule re-scored | network | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.58 (0.49–0.66) | 17/45 | 0/120 | 0 |
| after, same configuration | repo | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.95 (0.90–0.97) | 0/45 | 0/120 | 0 |
| after, same configuration | endpoint | 0.75 (0.68–0.81) | 1.00 (0.97–1.00) | 0.86 | 1.00 (0.97–1.00) | 0/45 | 0/120 | 0 |
| after, same configuration | network | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.00 (0.00–0.03) | 0/45 | 0/120 | 0 |
| after, agent rule re-scored | repo | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 1.00 (0.97–1.00) | 0/45 | 0/120 | 0 |
| after, agent rule re-scored | endpoint | 0.75 (0.68–0.81) | 1.00 (0.97–1.00) | 0.86 | 1.00 (0.97–1.00) | 0/45 | 0/120 | 0 |
| after, agent rule re-scored | network | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.99 (0.96–1.00) | 0/45 | 0/120 | 0 |
| after, dedicated connectors | repo | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.95 (0.90–0.97) | 0/45 | 0/120 | 0 |
| after, dedicated connectors | endpoint | 0.96 (0.92–0.98) | 1.00 (0.97–1.00) | 0.98 | 1.00 (0.97–1.00) | 4/45 | 0/120 | 0 |
| after, dedicated connectors | network | 1.00 (0.98–1.00) | 1.00 (0.97–1.00) | 1.00 | 0.99 (0.96–1.00) | 0/45 | 0/120 | 0 |

Families whose detection count differs between variants:

| Family | Label | before (published) | before, agent rule re-scored | after, same configuration | after, agent rule re-scored | after, dedicated connectors |
|---|---|---|---|---|---|---|
| endpoint:ep-browser-ai-ext | llm | 0/11 | 0/11 | 0/11 | 0/11 | 11/11 |
| endpoint:ep-cline | agent | 5/8 | 5/8 | 8/8 | 8/8 | 8/8 |
| endpoint:ep-copilot-ext | llm | 0/7 | 0/7 | 0/7 | 0/7 | 7/7 |
| endpoint:ep-goose | agent | 0/6 | 0/6 | 6/6 | 6/6 | 6/6 |
| endpoint:ep-lmstudio | llm | 0/8 | 0/8 | 0/8 | 0/8 | 8/8 |
| endpoint:ep-ollama-models | llm | 0/12 | 0/12 | 0/12 | 0/12 | 12/12 |
