# Contributing Guide

This document describes how to set up a local development environment, run the test suite, and follow the conventions used in this project.

> **Warning:** This repository contains intentional security vulnerabilities. All development must be done in isolated, non-production environments.

---

## Development Environment Setup

The project uses [uv](https://docs.astral.sh/uv/) for dependency and virtual-environment management. Install it before proceeding.

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Clone the repository and install all dependencies, including the development group:

```bash
git clone https://github.com/irishlab-io/vb-app.git
cd vb-app
uv sync
```

`uv sync` creates a virtual environment at `.venv/` and installs both the runtime and dev dependencies declared in `pyproject.toml`.

---

## Running the Application Locally

Copy and configure the environment file:

```bash
cp .env.example .env
# Edit .env: set DB_HOST=localhost for local PostgreSQL
```

Start the Flask development server:

```bash
uv run python -m vuln_bank.app
```

The application is available at `http://localhost:5000`. See [docs/installation.md](installation.md) for full setup instructions, including Docker Compose and database configuration.

---

## Running Tests

The project uses [pytest](https://docs.pytest.org/) with `pytest-cov` for coverage and `pytest-xdist` for parallel execution.

```bash
# Run the full test suite
uv run pytest

# Run only unit tests
uv run pytest -m unit

# Run a specific file
uv run pytest tests/unit/test_auth.py

# Run without parallel execution (useful for debugging)
uv run pytest -p no:xdist
```

Coverage reports are written to:

- Terminal: printed after each run
- HTML: `tests/coverage/html/index.html`
- XML: `tests/coverage/coverage.xml`

The minimum required coverage threshold is **60%**. The test run fails if coverage drops below this level.

### Test Markers

| Marker | Description |
|---|---|
| `unit` | Fast, isolated unit tests with mocked dependencies |
| `integration` | Tests that exercise multiple components together |
| `security` | Vulnerability-specific tests |
| `e2e` | End-to-end tests against a running application |

Mark new tests with the appropriate marker:

```python
import pytest

@pytest.mark.unit
def test_example():
    ...
```

### Test Fixtures

Shared fixtures are defined in `tests/conftest.py`. The most important fixture is the `psycopg2` connection-pool mock, which must be patched before importing `vuln_bank.app` so the module-level database initialisation does not attempt a real connection during test collection.

---

## Linting and Formatting

The project uses [ruff](https://docs.astral.sh/ruff/) for both linting and import sorting.

```bash
# Check for lint errors
uv run ruff check src/

# Auto-fix fixable lint errors
uv run ruff check --fix src/

# Check formatting
uv run ruff format --check src/

# Apply formatting
uv run ruff format src/
```

The ruff configuration is in `pyproject.toml` under `[tool.ruff]`. The line length is 128 characters and the target Python version is 3.9.

### Pre-commit Hooks

A `.pre-commit-config.yaml` is provided. Install the hooks to run linting automatically before each commit:

```bash
uv run pre-commit install
```

---

## Type Checking

The project uses [ty](https://github.com/astral-sh/ty) for type checking:

```bash
uv run ty check src/
```

---

## Project Structure

```
vb-app/
├── docs/               # Project documentation (this directory)
├── src/
│   └── vuln_bank/      # Main application package
│       ├── app.py              # Flask app factory and route registration
│       ├── auth.py             # JWT authentication helpers and API auth routes
│       ├── database.py         # PostgreSQL connection pool and schema init
│       ├── transaction_graphql.py  # GraphQL schema and resolvers
│       ├── ai_agent_ollama.py  # Ollama-backed AI customer support agent
│       ├── site_config.py      # Site-wide configuration helpers
│       ├── graphql/            # GraphQL type definitions
│       ├── static/             # CSS, JS, and uploaded files
│       └── templates/          # Jinja2 HTML templates
├── tests/
│   ├── conftest.py     # Shared fixtures (DB mock, app client, tokens)
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   └── e2e/            # End-to-end tests
├── data/               # Seed data scripts
├── infra/              # Infrastructure configuration (placeholder)
├── scripts/            # Utility scripts (placeholder)
├── compose.yml         # Docker Compose stack definition
├── Dockerfile          # Application container image
├── pyproject.toml      # Project metadata, dependencies, and tool configuration
├── uv.lock             # Locked dependency versions
├── .env.example        # Example environment variables
└── start.sh            # Container entrypoint (waits for DB, then starts Flask)
```

See [docs/architecture.md](architecture.md) for a detailed description of the application architecture.

---

## Adding a New Route

1. Add the route handler inside the appropriate `init_*_routes(app)` function in `src/vuln_bank/app.py` or `src/vuln_bank/auth.py`.
2. Register any new `init_*_routes` call in the `main()` function at the bottom of `app.py`.
3. If the route introduces a new vulnerability, document it in [docs/vulnerabilities.md](vulnerabilities.md).
4. Write a corresponding unit test in `tests/unit/`.

---

## Dependency Management

Runtime dependencies are declared in `[project.dependencies]` in `pyproject.toml`. Development dependencies are in `[dependency-groups] dev`. After editing `pyproject.toml`, regenerate the lockfile:

```bash
uv lock
```

To add a new runtime dependency:

```bash
uv add <package>
```

To add a new development dependency:

```bash
uv add --group dev <package>
```
