"""AI Review Gate: deterministic finding validation and synthesis.

The package is imported by .github/workflows/ai-review-gate.yml, which runs
the base-ref copy of it against the pull request's finding artifacts. It uses
only the standard library so it runs without the repository's pinned
toolchain, and it never imports pull-request code.
"""
