# Testing Guide

This document covers setting up a reproducible test environment and running ShadowScan's comprehensive test suites.

## Environment Setup

### Python Version

ShadowScan requires Python 3.11 or newer. Use a supported version:

```bash
python --version  # Verify 3.11+
```

### Virtual Environment (Recommended)

A virtual environment isolates dependencies and prevents system package conflicts:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### Dependency Installation

Install the project with all development and cloud SDKs:

```bash
python -m pip install -e ".[all]"
```

This installs:
- **dev**: pytest, pytest-cov, ruff, mypy, type stubs, responses, pip-audit, pre-commit
- **cloud**: AWS, Azure, GCP, OCI SDKs (required for test suite)
- **docs**: mkdocs and documentation toolchain

To install only dev dependencies without cloud SDKs (faster for linting-only work):

```bash
python -m pip install -e ".[dev]"
```

### Type Checking Dependencies

For full mypy support with type stubs:

```bash
python -m pip install types-PyYAML types-requests
```

These provide type information for `yaml` and `requests` libraries used throughout the codebase.

## Running Tests

### Quick Test (Single Test)

Validate the test environment works:

```bash
python -m pytest -q tests/unit/test_signatures.py::test_all_signatures_load_and_validate
```

This test requires no cloud credentials and verifies that all bundled signatures load successfully.

### Full Test Suite

Run the complete test suite with coverage collection:

```bash
make test
```

This runs:
- All unit tests
- Integration tests
- Acceptance tests
- Coverage collection (with fail_under=80% gate)

### Fast Testing (No Coverage)

For iterative development, run tests without coverage:

```bash
make test-fast
```

This stops at the first failure for quick feedback.

### Per-Connector Coverage Gate

After running the full test suite, enforce per-connector coverage minimums (≥75%):

```bash
make coverage-gate
```

Alternatively, generate and pass a coverage JSON report:

```bash
python -m coverage json -o /tmp/shadowscan-coverage.json
python -m tools.coverage_gate /tmp/shadowscan-coverage.json
```

## Quality Checks

### Linting

Check code style and common errors with ruff:

```bash
make lint
```

### Type Checking

Validate type safety with mypy:

```bash
make typecheck
```

If you see "Library stubs not installed" errors, install type packages:

```bash
python -m pip install types-PyYAML types-requests
```

### Signature Validation

Validate all YAML signature definitions:

```bash
python -m shadowscan.signatures.validate
```

### Dependency Audit

Check for known vulnerabilities:

```bash
make audit
```

### All Quality Gates

Run all local checks (the same suite CI validates):

```bash
make check
```

This runs: linting → type checking → signature validation → audit → tests → coverage gates → evaluation.

## Troubleshooting

### Dependency Version Conflicts

If you see "requires X but you have Y" warnings, ensure you're using the versions specified in `pyproject.toml`:

```bash
pip list | grep -E "pyyaml|requests|pyjwt|urllib3|regex"
```

For version mismatches, uninstall and reinstall:

```bash
pip install --force-reinstall --no-cache-dir 'pyyaml>=6.0.3' 'requests>=2.34.2'
```

### Import Errors on Test Run

If you see `ModuleNotFoundError`, ensure the dev extras are installed:

```bash
python -m pip install -e ".[all]" --upgrade
```

### Mypy Errors on Missing Imports

mypy may report "library stubs not installed" for `yaml` and `requests`. Install type packages:

```bash
python -m mypy --install-types
```

Or explicitly:

```bash
pip install types-PyYAML types-requests
```

### Test Timeout or Hang

Some tests make real cloud API calls (for canaries). If a test hangs:

1. Check your cloud credentials are not expired
2. Cancel with Ctrl+C and skip canary tests:

```bash
pytest -q tests/ -k "not canary"
```

### Coverage Below Gate

If coverage is below 80% aggregate or 75% per-connector:

1. Identify gaps: `coverage report --skip-empty`
2. Write tests for uncovered code paths
3. Run `make coverage-gate` again

## Integration Tests & Fixtures

The test suite uses offline fixtures to avoid live cloud API calls:

- **fixtures/**: Sanitized cloud exports, YAML configs, and code samples
- **tests/fixtures/sample_repo/**: A minimal repo for code scanning tests
- **tools/evaluation/**: Regression corpus with documented test cases

Tests use these fixtures without requiring credentials. For live tenant testing, see [canaries.md](canaries.md) and [acceptance.md](../tools/acceptance/README.md).

## CI/CD Integration

The GitHub Actions CI runs the same checks:

- **ci.yml**: Runs `make check` on Python 3.11, 3.12, 3.13
- **release.yml**: Validates packaging and release candidate evidence

For details, see `.github/workflows/`.

## Contributing Changes

Before submitting a pull request:

1. Set up a virtual environment
2. Install with `pip install -e ".[all]"`
3. Install pre-commit hooks: `make install-hooks`
4. Make your changes
5. Run `make check` to validate
6. Commit with a clear message (pre-commit hooks will lint)

If `make check` fails:
- Fix linting: `ruff check --fix shadowscan tests tools`
- Add type annotations: review mypy output and add stubs where needed
- Write or fix tests to maintain coverage
- Run specific test: `pytest tests/unit/test_x.py -v`

## Advanced: Custom Test Run

Run a subset of tests by pattern:

```bash
pytest tests/ -k "gateway" -v              # All gateway tests
pytest tests/unit/ --co -q | head -20     # List first 20 tests
pytest tests/ -x                           # Stop on first failure
pytest tests/ --tb=short                   # Minimal traceback
```

For more pytest options, see `pytest --help` or the [pytest docs](https://docs.pytest.org/).
