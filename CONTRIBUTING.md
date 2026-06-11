# Contributing

1. Fork and clone the repo, then install in editable mode with dev tools: `pip install -e ".[dev]"` (Python 3.10+).
2. Run the test suite with `pytest`; lint with `ruff check .` and format with `black infra_auditor tests`.
3. CI runs the same three gates on Linux and Windows across Python 3.10-3.12 — all must pass before merge.
4. New checks go in `infra_auditor/checks/` (subclass `BaseCheck`, register with `@CheckRegistry.register`) and need tests in `tests/`.
5. Keep pull requests focused: one fix or feature per PR, with a short description of what changed and why.
6. Bug reports and feature ideas are welcome as GitHub issues; for security problems use [SECURITY.md](SECURITY.md) instead.
