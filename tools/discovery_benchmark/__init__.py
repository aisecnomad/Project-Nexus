"""Shadow AI agent discovery benchmark on pinned real-world repositories.

The package holds a tool-neutral fact taxonomy, an evidence extractor used to
label ground truth, adapters that run external discovery tools and normalize
their output, an isolated runner, a scorer and a report generator. See
``benchmarks/shadow-ai-discovery/README.md`` for the design and its limits.
Nothing here executes repository content; third-party tools are run as an
unprivileged user against read-only checkouts with network access disabled.
"""
