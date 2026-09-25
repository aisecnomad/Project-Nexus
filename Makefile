.DEFAULT_GOAL := help
SHELL := /bin/bash
export PYTHON_BASE_DIGEST

# --- Development -----------------------------------------------------------

.PHONY: install
install: ## Install in editable mode with dev + cloud extras
	python -m pip install -e ".[all]"

.PHONY: install-dev
install-dev: ## Install with dev extras only (no cloud SDKs)
	python -m pip install -e ".[dev]"

.PHONY: install-hooks
install-hooks: ## Install pre-commit hooks
	pip install pre-commit
	pre-commit install

# --- Quality ---------------------------------------------------------------

.PHONY: lint
lint: ## Run ruff linter
	ruff check shadowscan tests tools

.PHONY: typecheck
typecheck: ## Run mypy type checker
	mypy shadowscan tools/evaluation tools/canaries

.PHONY: test
test: ## Run test suite with coverage
	python -m pytest -q --cov=shadowscan --cov-report=term-missing --cov-fail-under=80

.PHONY: test-fast
test-fast: ## Run tests without coverage (faster iteration)
	python -m pytest -q -x

.PHONY: coverage-gate
coverage-gate: ## Enforce per-connector coverage floor
	python -m coverage json -o /tmp/shadowscan-coverage.json
	python -m tools.coverage_gate /tmp/shadowscan-coverage.json

.PHONY: signatures
signatures: ## Validate all signature schemas and regexes
	python -m shadowscan.signatures.validate

.PHONY: audit
audit: ## Audit dependencies for known vulnerabilities
	pip-audit --progress-spinner off

.PHONY: evaluate
evaluate: ## Run the local detection corpus subset
	python -m tools.evaluation.evaluate
	python -m tools.evaluation.evaluate --corpus tools/evaluation/public_corpus.json
	python -m tools.evaluation.evaluate --corpus tools/evaluation/independent_corpus.json \
		--annotations tools/evaluation/independent_annotations.json

.PHONY: check
check: lint typecheck signatures audit test coverage-gate evaluate ## Run local quality checks
	@echo "All checks passed."

# --- Build -----------------------------------------------------------------

.PHONY: build
build: ## Build distributable wheel
	python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist

.PHONY: wheel-validate
wheel-validate: build ## Validate the wheel installs and works outside checkout
	python -m venv /tmp/shadowscan-wheel-test
	/tmp/shadowscan-wheel-test/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
	/tmp/shadowscan-wheel-test/bin/python -m pip install --no-deps dist/*.whl
	/tmp/shadowscan-wheel-test/bin/python -m pip check
	cd /tmp && /tmp/shadowscan-wheel-test/bin/python -m shadowscan.signatures.validate
	cd /tmp && /tmp/shadowscan-wheel-test/bin/shadowscan --help
	rm -rf /tmp/shadowscan-wheel-test

.PHONY: docker
docker: ## Build worker with PYTHON_BASE_DIGEST=<approved 64-character hex digest>
	@if [[ ! "$${PYTHON_BASE_DIGEST:-}" =~ ^[a-f0-9]{64}$$ ]]; then \
		echo "Set PYTHON_BASE_DIGEST to an approved 64-character python:3.12-slim-bookworm image index digest" >&2; \
		exit 2; \
	fi
	docker build --build-arg "PYTHON_BASE_DIGEST=$${PYTHON_BASE_DIGEST}" --tag shadowscan:local .

.PHONY: docker-test
docker-test: docker ## Run container smoke test
	docker run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --entrypoint python shadowscan:local \
		-c 'import os; assert os.geteuid() == 65532; print("Non-root: OK")'
	docker run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --entrypoint python shadowscan:local \
		-m shadowscan.signatures.validate

# --- Demo ------------------------------------------------------------------

.PHONY: demo
demo: ## Run the bundled offline demo scan
	shadowscan scan -c examples/shadowscan.offline.yaml --format table

.PHONY: demo-sarif
demo-sarif: ## Run offline demo with SARIF output
	shadowscan scan -c examples/shadowscan.offline.yaml --format sarif -o shadowscan.sarif
	@echo "SARIF written to shadowscan.sarif"

# --- Docs ------------------------------------------------------------------

.PHONY: docs
docs: ## Build documentation site locally
	pip install -q mkdocs-material mkdocs-minify-plugin
	mkdocs build

.PHONY: docs-serve
docs-serve: ## Serve documentation site with live reload
	pip install -q mkdocs-material mkdocs-minify-plugin
	mkdocs serve

# --- Cleanup ---------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts and caches
	rm -rf dist build *.egg-info .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov
	rm -f shadowscan.sarif
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# --- Help ------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'
